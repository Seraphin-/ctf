# Conversation (Forensics 26, 384 solves)

The first thing to do with a big dump like this is to check for some plaintext communications, and we find a TCP stream that records the following conversation:

```
Hello there, yakuhito
Hello, John! Nice to hear from you again. It's been a while.
I'm sorry about that... the folks at my company restrict our access to chat apps.
Do you have it?
Have what?
The thing.
Oh, sure. Here it comes:
JP1ADIA7DJ5hLI9zpz9gK21upzgyqTyhM19bLKAsLI9hMKqsLz95MaWcMJ5xYJEuBQR3LmpkZwx5ZGL3AGS9Pt==
Doesn't look like the thing
A guy like you should know what to do with it.
May I get a hint? :)
rot13
Got it. Thanks.
```

The conversation mentions rot13 and the data looks like base64, so after first rot13ing the data then decoding it we get the flag.

Flag: `X-MAS{Anna_from_marketing_has_a_new_boyfriend-da817c7129916751}`