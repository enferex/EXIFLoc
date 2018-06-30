#define _DEFAULT_SOURCE
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Great resources:
 * TIFF (Format of Exif data):
 * https://www.adobe.io/content/udp/en/open/standards/TIFF/_jcr_content/contentbody/download/file.res/TIFF6.pdf
 *
 * Exif/JPEG:
 * https://www.media.mit.edu/pia/Research/deepview/exif.html
 * http://www.exif.org/Exif2-2.PDF (Clear definition of 'rational').
 *
 * GPSInfo EXIF Tags:
 * https://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/GPS.html
 *
 * My other program: TEPSniff (another TIFF parser)
 * the endian code came from that project.
 * https://github.com/enferex/tepsniff/
 */

#define MARKER_SOI 0xD8 // Start of Image
#define MARKER_EOI 0xD9 // End of Image
#define MARKER_SOS 0xDA // Start of Stream

#define _PR(_fd, _pre, _msg, ...)                                              \
  do {                                                                         \
    fprintf(_fd, _pre " " _msg "\n", ##__VA_ARGS__);                           \
  } while (0)

#define FAIL(_msg, ...)                                                        \
  do {                                                                         \
    _PR(stderr, "[!]", _msg, ##__VA_ARGS__);                                   \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#define PR(...) _PR(stdout, "[-]", __VA_ARGS__)

#ifdef DEBUG
#define DBG(...) _PR(stdout, "[+]", __VA_ARGS__)
#else
#define DBG(...)
#endif

/* Macros to handle endiness of TIFF. 4 cases.
 * This was originally from my other project:
 * https://github.com/enferex/tepsniff/
 * 1) BE system and TIFF is BE
 * 2) BE system and TIFF is LE
 * 3) LE system and TIFF is BE
 * 4) LE system and TIFF is LE
 */
#define IS_BE(_h) (_h->hdr.byte_order == 0x4D4D)
#if __BYTE_ORDER == __BIG_ENDIAN
#define NATIVE2(_h, _v) (IS_BE(_h) ? (_v) : le16toh(_v))
#define NATIVE4(_h, _v) (IS_BE(_h) ? (_v) : le32toh(_v))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define NATIVE2(_h, _v) (IS_BE(_h) ? htobe16(_v) : (_v))
#define NATIVE4(_h, _v) (IS_BE(_h) ? htobe32(_v) : (_v))
#else
#error "Middle endian not supported."
#endif

typedef struct _coords_t { uint32_t lat, lon; } coords_t;

typedef struct _ifd_entry_t {
  // These reamain in their original byte order,
  // readers of this should use NATIVE to make sense of these values.
  uint16_t tag;
  uint16_t type;
  uint32_t n_components;
  uint32_t value_offset;
} ifd_entry_t;

// This is really the entire IFD but with a next pointer so that we can chain
// IFDs together.
typedef struct _ifd_t {
  uint16_t n_entries;
  ifd_entry_t *entries;
  struct _ifd_t *next;
} ifd_t;

typedef struct _tiff_hdr_t {
  uint16_t byte_order; // "II": Little endian, "MM": Big endian.
  uint16_t universe;   // Must be 42.
  uint32_t offset;     // Initial IFD offset
} tiff_hdr_t;

typedef struct _tiff_t {
  tiff_hdr_t hdr;
  ifd_t *ifds;
} tiff_t;

typedef struct _exif_t {
#define EXIF_HDR_BYTES 6 // This is the first 6 bytes in 'data': 'Exif00'
  const char *filename;
  size_t size;
  uint8_t *data;
  tiff_t *tiff;
} exif_t;

// This represents the tag to search for.
typedef struct _locator_t {
  uint16_t tag;  // IFD tag  (native endian)
  uint16_t type; // IFD type (native endian)

  // This is called back if tag is a match when searching IFDs.
  void (*cb)(const exif_t *e, const ifd_entry_t *i);
} locator_t;

// This represents a collection of locator_t instances.
typedef struct _locator_list_t {
  const int n_locators;
  const locator_t *locators;
} locator_list_t;

static void usage(const char *execname) {
  printf("Usage: %s [jpeg ...]\n", execname);
  exit(EXIT_SUCCESS);
}

static int safe_fgetc(FILE *fp) {
  const int byte = fgetc(fp);
  if (byte == EOF)
    FAIL("Error reading input file.");
  return byte;
}

// Returns true if the marker is located.
static uint8_t read_marker(FILE *fp, _Bool fatal) {
  const int byte = safe_fgetc(fp);
  if (byte != 0xFF) {
    // We did not get a marker header which we expected.
    if (fatal)
      FAIL("Invalid start of marker, expected 0xFF.");
    return 0;
  }
  return (uint8_t)safe_fgetc(fp);
}

static uint16_t read_marker_size(FILE *fp) {
  const uint8_t hi = safe_fgetc(fp);
  const uint8_t lo = safe_fgetc(fp);
  return (hi << 8) | lo;
}

static _Bool find_marker(FILE *fp, int marker) {
  while (!feof(fp) && !ferror(fp)) {
    const uint8_t current_marker = read_marker(fp, true);
    DBG("Marker: 0x%02x", current_marker);
    if (current_marker == marker)
      return true;

    // Special cases.
    if (current_marker == MARKER_SOS)
      return false; // This will lead to the EOI, so we are done with this
                    // image.
    else if (current_marker == MARKER_SOI || current_marker == MARKER_EOI)
      continue;
    else {
      // Skip bytes if not SOI, SOS, or EOI.
      const uint16_t skip = read_marker_size(fp) - 2;
      DBG("Skipping %d bytes.", skip);
      if (fseek(fp, skip, SEEK_CUR) != 0)
        FAIL("Error seeking to next marker.");
    }
  }

  return false;
}

static void free_exif(exif_t *ex) {
  free(ex->tiff);
  free(ex->data);
  free(ex);
}

// Given an exif and an offset, read data from the exif data blob.
static _Bool read_data_from_exif(void *dest, uint64_t offset, size_t size,
                                 const exif_t *ex) {
  if (offset + size > ex->size)
    return false;
  return memcpy(dest, ex->data + offset, size) != NULL;
}

// This updates offset to point to the next ifd to read (or 0 if done).
static ifd_t *read_ifd(const exif_t *ex, uint64_t *offset) {
  // Read in the number of entries for this IFD.
  uint16_t n_entries;
  const tiff_t *tiff = ex->tiff;
  if (!read_data_from_exif((void *)&n_entries, *offset, sizeof(n_entries), ex))
    FAIL("Error loading IFD entry count.");
  n_entries = NATIVE2(tiff, n_entries);
  *offset += sizeof(n_entries);

  ifd_t *ifd = calloc(1, sizeof(ifd));
  if (!ifd)
    FAIL("Error allocating memory to store an IFD.");

  // Advance to the start of the first entry.
  DBG("Reading %d entries (%zu bytes) starting at offset 0x%lx.", n_entries,
      n_entries * sizeof(ifd_entry_t), *offset);
  ifd->n_entries = n_entries;

  // Instead of allocating more memory, and IFD entries are contiguous,
  // just point the start of the entires to 'entries' in this header.
  ifd->entries = (ifd_entry_t *)(ex->data + *offset);
  *offset += n_entries * sizeof(ifd_entry_t);

  // Offset to next IFD, or 0 if there are no more to read..
  const uint32_t next = *(uint32_t *)(ex->data + *offset);
  if (next)
    *offset = NATIVE4(tiff, next) + EXIF_HDR_BYTES;
  else
    *offset = 0;
  DBG("Next IFD offset is: 0x%lx.", *offset);
  return ifd;
}

// From the spec: A rational is two 32bit integers, first 4 bytes is numerator
// and second 4 bytes is denominator.
static uint32_t rational_to_value(const exif_t *ex, uint64_t rational) {
  uint32_t numerator = (uint32_t)(rational & 0xFFFFFFFF);
  uint32_t denominator = (uint32_t)(rational >> 32);
  return (uint32_t)(numerator / denominator);
}

// A single rational is 8 bytes (two 4 bytes components).
static void read_n_rationals(const uint8_t *data, int n, uint64_t *results) {
  for (int i = 0; i < n; ++i)
    results[i] = *(uint64_t *)(data + (i * sizeof(uint64_t)));
}

static void exif_to_tiff(exif_t *ex) {
  tiff_t *tiff = calloc(1, sizeof(tiff_t));
  if (!tiff)
    FAIL("Error allocating memory to store Exif in TIFF format.");

  ex->tiff = tiff;

  // The TIFF header follows the EXIF header, so use the exif header size as the
  // offset.
  if (!read_data_from_exif((void *)tiff, EXIF_HDR_BYTES, sizeof(tiff->hdr), ex))
    FAIL("Error reading TIFF header.");

  // Fix up the header so that we can make sense of it.
  tiff->hdr.universe = NATIVE2(tiff, tiff->hdr.universe);
  tiff->hdr.offset = NATIVE4(tiff, tiff->hdr.offset);

  // Sanity check.
  if (tiff->hdr.universe != 42)
    FAIL("Invalid TIFF format.");

  // Initialize the IFD scan by placing the offset at the beginning of the TIFF
  // data.  We advance past the first header (EXIF) since the TIFF data offset
  // is calculated starting at the beginning of the TIFF blob (after the EXIF
  // header).
  uint64_t off = EXIF_HDR_BYTES + tiff->hdr.offset;

  ifd_t *prev = NULL;
  while (off && off < ex->size) {
    // Read in all of the IFD entries, off will be zero at the end.
    ifd_t *ifd = read_ifd(ex, &off);
    if (prev)
      prev->next = ifd;
    else
      tiff->ifds = ifd;
    prev = ifd;
  }
}

static exif_t *read_exif(const char *filename) {
  DBG("Loading %s", filename);
  FILE *fp = fopen(filename, "r");
  if (!fp)
    FAIL("Error opening %s: %s", filename, strerror(errno));

  exif_t *ex;
  if (!(ex = calloc(1, sizeof(exif_t))))
    FAIL("Error allocating memory to store an exif instance.");

  ex->filename = filename;

  // Find the start of the image marker: SOI.
  const uint8_t header_marker = read_marker(fp, false);
  if (header_marker != 0xD8) {
    DBG("%s: Not a file format we know how to handle.", filename);
    goto oops; // Not an image format we know how to handle.
  }

  // Find the start of APP1 (where exif lives).
  if (!find_marker(fp, 0xE1)) {
    DBG("%s: Could not locate exif data.", filename);
    goto oops; // Couldn't find exif.
  }

  // Assume we have a valid app1, read in its contents.
  ex->size = read_marker_size(fp) - 2;
  if (!(ex->data = calloc(1, ex->size)))
    FAIL("Error allocating exif data contents.");
  if (fread(ex->data, 1, ex->size, fp) != ex->size)
    FAIL("Error reading exif contents.");

  fclose(fp);

  // Verify the exif header and return NULL if invalid.
  if (strncmp((const char *)ex->data, "Exif", 4) == 0 && ex->data[4] == 0 &&
      ex->data[5] == 0) {
    // Set the TIFF data.
    DBG("Found EXIF data: %zu bytes.", ex->size);
    exif_to_tiff(ex);
    return ex;
  }

oops:
  free(ex);
  return NULL;
}

#ifdef DEBUG
static void dump(const exif_t *ex) {
  if (!ex->tiff)
    return;

  int ifd_number = 0;
  for (const ifd_t *ifd = ex->tiff->ifds; ifd; ifd = ifd->next) {
    for (int i = 0; i < ifd->n_entries; ++i) {
      const ifd_entry_t *entry = ifd->entries + i;
      const uint16_t tag = NATIVE2(ex->tiff, entry->tag);
      DBG("IFD:%d -- Tag 0x%04x", ifd_number, tag);
    }
    ++ifd_number;
  }
}
#endif // DEBUG

// Scan each locator to see if it matches the tag.
static void callback_if_found(const locator_list_t *list, const exif_t *ex,
                              const ifd_entry_t *entry) {
  const uint16_t tag = NATIVE2(ex->tiff, entry->tag);
  const locator_t *locs = list->locators;
  for (int i = 0; i < list->n_locators; ++i)
    if (locs[i].tag == tag)
      locs[i].cb(ex, entry);
}

// Scan each IFD entry in ex.
static void locate_tags(const exif_t *ex, const locator_list_t *list) {
  assert(ex->tiff && "No TIFF/EXIF tags available.");
  assert(list && list->n_locators && "No locators defined.");
  for (const ifd_t *ifd = ex->tiff->ifds; ifd; ifd = ifd->next) {
    for (uint16_t i = 0; i < ifd->n_entries; ++i) {
      const ifd_entry_t *entry = ifd->entries + i;
      callback_if_found(list, ex, entry);
    }
  }
}

// Given and IFD and tag, return a ptr to the tag or NULL if it's not found.
static const ifd_entry_t *find_tag(const exif_t *ex, const ifd_t *ifd,
                                   uint16_t tag) {
  assert(ifd && "Invalid IFD to search.");
  for (uint16_t i = 0; i < ifd->n_entries; ++i) {
    const ifd_entry_t *entry = ifd->entries + i;
    const uint16_t entry_tag = NATIVE2(ex->tiff, entry->tag);
    if (entry_tag == tag)
      return entry;
  }

  return NULL;
}

static void gps_print_coords(const exif_t *ex, const ifd_entry_t *lat,
                             const ifd_entry_t *lat_ref, const ifd_entry_t *lon,
                             const ifd_entry_t *lon_ref, const ifd_entry_t *alt,
                             const ifd_entry_t *alt_ref) {
  struct {
    uint32_t deg, min, sec;
    char dir;
  } lat_dms, lon_dms;

  uint64_t rationals[3];
  printf("%s", ex->filename);
  if (lat) {
    const uint32_t off = NATIVE4(ex->tiff, lat->value_offset);
    read_n_rationals(ex->data + EXIF_HDR_BYTES + off, 3, rationals);
    lat_dms.deg = rational_to_value(ex, rationals[0]);
    lat_dms.min = rational_to_value(ex, rationals[1]);
    lat_dms.sec = rational_to_value(ex, rationals[2]);
    lat_dms.dir = lat_ref ? (char)lat_ref->value_offset : '?';
    printf(", %uº%u'%u\"%c", lat_dms.deg, lat_dms.min, lat_dms.sec,
           lat_dms.dir);
  }
  if (lon) {
    const uint32_t off = NATIVE4(ex->tiff, lon->value_offset);
    read_n_rationals(ex->data + EXIF_HDR_BYTES + off, 3, rationals);
    lon_dms.deg = rational_to_value(ex, rationals[0]);
    lon_dms.min = rational_to_value(ex, rationals[1]);
    lon_dms.sec = rational_to_value(ex, rationals[2]);
    lon_dms.dir = lon_ref ? (char)lon_ref->value_offset : '?';
    printf(", %uº%u'%u\"%c", lon_dms.deg, lon_dms.min, lon_dms.sec,
           lon_dms.dir);
  }
  if (alt) {
    const uint32_t off = NATIVE4(ex->tiff, alt->value_offset);
    read_n_rationals(ex->data + EXIF_HDR_BYTES + off, 1, rationals);
    const uint32_t meters = rational_to_value(ex, rationals[0]);
    printf(", %c%u meters",
           (meters && alt_ref && !alt_ref->value_offset) ? '-' : ' ', meters);
  }
  if (lat && lon) {
    const float lat_dd = (float)lat_dms.deg + (float)lat_dms.min / 60.0f +
                         (float)lat_dms.sec / 3600.0f;
    const float lon_dd = (float)lon_dms.deg + (float)lon_dms.min / 60.0f +
                         (float)lon_dms.sec / 3600.0f;
    printf(", <https://www.google.com/maps/place/@%f%c,%f%c>", lat_dd,
           lat_dms.dir, lon_dd, lon_dms.dir);
  }
  putc('\n', stdout);
}

static void gps_tag_handler(const exif_t *ex, const ifd_entry_t *gps_tag) {
  uint64_t offset = NATIVE4(ex->tiff, gps_tag->value_offset) + EXIF_HDR_BYTES;
  DBG("Located GPS tag at offset 0x%lx", offset);
  ifd_t *ifd = read_ifd(ex, &offset);
  if (!ifd) {
    DBG("Error locating GPS IFD.");
    return;
  }

  // Version.
  const ifd_entry_t *ver = find_tag(ex, ifd, 0x0000);
  if (!ver) {
    DBG("No GPS version data found.");
    return;
  }

  // Coordinate reference values.
  const ifd_entry_t *lat_ref = find_tag(ex, ifd, 0x0001); // "N or S"
  const ifd_entry_t *lon_ref = find_tag(ex, ifd, 0x0003); // "E or W"
  const ifd_entry_t *alt_ref = find_tag(ex, ifd, 0x0005); // 1 or 0 (asl or bsl)

  // Coordinates.
  const ifd_entry_t *lat = find_tag(ex, ifd, 0x0002);
  const ifd_entry_t *lon = find_tag(ex, ifd, 0x0004);
  const ifd_entry_t *alt = find_tag(ex, ifd, 0x0006);

  // Print.
  gps_print_coords(ex, lat, lat_ref, lon, lon_ref, alt, alt_ref);
}

int main(int argc, char **argv) {
  if (argc == 0)
    usage(argv[0]);

  // Create the locator objects.  Basically just a key and a callback,
  // which is what we use for identifying EXIF tags we are interested in.
  locator_t locator_entries[] = {
      {0x8825, 0x0000, gps_tag_handler} // GPS tag and some type.
  };
  const locator_list_t locators = {.n_locators = sizeof(locator_entries) /
                                                 sizeof(locator_entries[0]),
                                   .locators = locator_entries};

  // For each file specified on the command line.
  for (int i = 1; i < argc; ++i) {
    exif_t *ex;
    if ((ex = read_exif(argv[i]))) {
#ifdef DEBUG
      dump(ex);
#endif
      // Search.
      locate_tags(ex, &locators);
      free_exif(ex);
    }
  }

  return 0;
}
