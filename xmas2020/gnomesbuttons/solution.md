# Gnome's Buttons v4 (Web 498, 7 solves)

This is a spicy guess challenge.

We're given a site with buttons that have their text randomly printed a lot of languages. There's also a hint to try refreshing the page. Refreshing the page repeatedly we find a link to `/?start=1` then `/?start=1&role=user`. The leftmost box now links back to `/?start=1&role=user&start=1` but hints that "we have the wrong start". Guessing `/?start=2020&role=user` gives a different "welcome" message.

We then guess `/?start=2020&role=admin` to get a "PERMISSION DENIED" message and some hidden html referencing (this paper)[http://www.madlab.it/slides/BHEU2011/whitepaper-bhEU2011.pdf]. One concept it mentions is different prioritization of URL parameters between backend and frontend. One way we might exploit that is encoding the role parameter twice, once for "user" and once for "admin". If we're lucky, the backend would pick one as the parameter and the WAF the other.

And indeed, `/?start=2020&role=user&role=admin` gets us the flag...

Flag: `X-MAS{idontwannafindbugsintheamericanlanguageanymore}`

Looking at the source code, seems like the author cheated by checking the query string exactly rather than having a real backend/waf confusion :angry: