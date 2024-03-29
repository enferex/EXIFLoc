### EXIFLoc: Extract GPS coordinates from an image file.

#### What
EXIFLoc is a simple EXIF parser that only cares about GPS metadata
stored within an image file (.jpg).  Sure, there are a bajillion other EXIF
tools available, but EXIFLoc has a philosophy: keep it simple.  There are no
additional arguments to this tool except for the list of image files to scan.

If GPS data is found within an image file, the following data is displayed:
`<file name>, <latitude>, <longitude>, <altitude>, <google maps url to that coordinate>`

#### Caveat
There might be some floating point error presented in the generated URL and 
probably some round-off error in the coordinates.

#### References
* TIFF (Format of EXIF data):
  * https://www.adobe.io/content/udp/en/open/standards/TIFF/_jcr_content/contentbody/download/file.res/TIFF6.pdf
* Exif/JPEG:
  * https://www.media.mit.edu/pia/Research/deepview/exif.html
  * http://www.exif.org/Exif2-2.PDF (Clear definition of 'rational').
* GPSInfo EXIF Tags:
  * https://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/GPS.html
* My other program: TEPSniff (another TIFF parser)
  the endian code came from that project.
  * https://github.com/enferex/tepsniff/
* Degree, minute, second (dms), to decimal degrees:
  * https://www.rapidtables.com/convert/number/degrees-minutes-seconds-to-degrees.html
* Decimal degrees to dms:
  * https://www.calculatorsoup.com/calculators/conversions/convert-decimal-degrees-to-degrees-minutes-seconds.php
* EXIFTool (great tool for exploring the format of EXIF data):
  * https://www.sno.phy.queensu.ca/~phil/exiftool/
* Wikipedia: For figuring out how to encode the google maps urls.

#### Contact
enferex, https://github.com/enferex
