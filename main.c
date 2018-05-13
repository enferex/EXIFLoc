#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#define MARKER_SOI 0xD8 // Start of Image
#define MARKER_EOI 0xD9 // End of Image
#define MARKER_SOS 0xDA // Start of Stream


#define _PR(_fd, _pre, _msg, ...)        \
  do {                                   \
    fprintf(_fd, _pre " " _msg "\n", ##__VA_ARGS__); \
  } while (0)

#define FAIL(_msg, ...)                    \
  do {                               \
    _PR(stderr, "[!]", _msg, ##__VA_ARGS__); \
    exit(EXIT_FAILURE);              \
  } while (0)

#define PR(...) _PR(stdout, "[-]", __VA_ARGS__)

#ifdef DEBUG
#define DBG(...) _PR(stdout, "[+]",  __VA_ARGS__)
#else
#define DBG(...)
#endif

typedef struct {uint32_t lat, lon; } coords_t;

static void usage(const char *execname) {
  printf("Usage: %s [jpeg ...]\n", execname);
  exit(EXIT_SUCCESS);
}

static void display(const char *filename, const coords_t *coords) {
  assert(coords   && "No coords presented.");
  assert(filename && "No filename presented.");
  printf("%s: %u, %u \n", filename, coords->lat, coords->lon);
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

// Brute-force scan to look for the value 'marker' in the file stream.
#if 0
static _Bool seek_to_next(FILE *fp, uint8_t marker) {
  while (!feof(fp) && !ferror(fp)) {
    const uint8_t byte = safe_fgetc(fp);
    if (byte == 0xFF && (safe_fgetc(fp) == marker)) {
      fseek(fp, -2, SEEK_CUR);
      return true;
    }
  }
  return false;
}
#endif // if 0

static _Bool find_marker(FILE *fp, int marker) {
  while (!feof(fp) && !ferror(fp)) {
    const uint8_t current_marker = read_marker(fp, true);
    DBG("Marker: 0x%02x", current_marker);
    if (current_marker == marker)
      return true;

    // Special cases.
    if (current_marker == MARKER_SOS)
      return false; // This will lead to the EOI, so we are done with this image.
      //return seek_to_next(fp, MARKER_EOI);
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

typedef struct _exif_t {
  size_t   size;
  uint8_t *data;
} exif_t;

static exif_t *read_exif(const char *filename) {
  DBG("Loading %s", filename);
  FILE *fp = fopen(filename, "r");
  if (!fp) 
    FAIL("Error opening %s: %s", filename, strerror(errno));

  exif_t *ex;
  if (!(ex = calloc(1, sizeof(exif_t))))
    FAIL("Error allocating memory to store an exif instance.");

  // Find the start of the image.
  const uint8_t header_marker = read_marker(fp, false);
  if (header_marker != 0xD8) {
    DBG("%s: Not a file format we know how to handle.", filename);
    goto oops; // Not an image format we know how to handle. 
  }

  // Find the start of APP1 (where exif lives).
  if (!find_marker(fp, 0xE1)) {
    DBG("%s: Could not locate EXIF data.", filename);
    goto oops; // Couldnt find exif.
  }

  // Assume we have a valid app1, read in its contents.
  ex->size = read_marker_size(fp) - 2;
  if (!(ex->data = calloc(1, ex->size)))
    FAIL("Error allocating exif data contents.");
  if (fread(ex->data, 1, ex->size, fp) != ex->size)
    FAIL("Error reading exif contents.");

  fclose(fp);

  // Verify the exif header.  Return NULL if invalid.
  if (strncmp((const char *)ex->data, "Exif", 4) == 0 &&
      ex->data[4] == 0  && ex->data[5] == 0) {
    DBG("%s: Located %zu bytes of Exif data.", filename, ex->size);
    return ex;
  }

oops:
    free(ex);
    return NULL;
}

static _Bool read_exif(const exif_t *ex) {
  return true;
}

int main(int argc, char **argv) {
  if (argc == 0)
    usage(argv[0]);

  // We only care about GPS markers.
  //locator_t locators[] = {
  //};

  // For each file specified on the command line.
  for (int i=1; i<argc; ++i) {
    exif_t *ex = read_exif(argv[i]);
    parse_exif(ex);
    if (!ex)
      continue;
    free(ex);
  }

  return 0;
}
