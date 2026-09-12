#include <cups/cups.h>
#include <cups/file.h>
#include <cups/http.h>
#include <cups/ipp.h>

// cups/dnssd.h is a CUPS 3-only addition; CUPS 2 has no equivalent header.
#ifdef CUPS_RS_CUPS3
#include <cups/dnssd.h>
#endif
