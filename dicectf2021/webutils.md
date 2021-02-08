# Web Utils
The POSTed json for creating pastes/links expands the data with `...`, allowing us to overwrite the `type` parameter in createPaste such that we submit a URL as if it were a paste. This bypasses the URL check, and we can just provide a `javascript:` URL to get XSS.
