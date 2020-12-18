# Gnome's Buttons v4 (Web 498, 7 solves)

Better writeup coming later?

Spicy guess(?) challenge. We're given a site with buttons and a lot of languages. Refreshing the page repeatedly we find a link to `/?start=1` then `/?start=1&role=user`. The leftmost box now links back to `/?start=1&role=user&start=1` but hints that "we have the wrong start". Guessing `/?start=2020&role=user` gives a different "welcome" message. We then guess `/?start=2020&role=admin` to get a "PERMISSION DENIED" message and some hidden html referencing (this paper)[http://www.madlab.it/slides/BHEU2011/whitepaper-bhEU2011.pdf]. The paper might be somewhat bait with the injection but one concept it mentions is different prioritization of URL parameters between backend and frontend. And indeed, `/?start=2020&role=user&role=admin` gets us the flag...

Flag: `X-MAS{idontwannafindbugsintheamericanlanguageanymore}`