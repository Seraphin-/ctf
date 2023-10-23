# Santa's consolation (Web 50, 285 solves)

(I'm not sure where I put the solve script for this)
The javascript code for the challenge implements a flagchecker. It does the following:
- Ensure none of the characters ateiz are in the input
- Replace 4 with a, 3 with e, 1 with i, t with 7, and z with \_.
- Convert the input into an array.
- Join the array into a string on the string '[]' (e.x. test -> t[]e[]s[]t)
- urlencode the string
- Split it into an array
- Replace each character with its decimal code
- Join the array on the string '|'
- Prepend some bytes and convert it to base64
- Check if it matches a base64 encoded string.
- If it matches, output the flag by wrapping the input with X-MAS{}

To get the flag we just need to perform the reverse opereations on the base64 string.
- Decode the base64
- Remove the first few bytes "REDACTED"
- Split the string on '|' into an array
- Replace each entry with its character from decimal
- Join it into a string
- urldecode the string
- Split the string on '[]' into an array
- Join it into a string
- Replace the leetspeak
