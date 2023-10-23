# PHP Master (Web 33, 325)

We need to find two inputs of the same length that evaluate to equal, don't contain the letter "e", and don't start with "0". Most of the tricks on Google are blocked by these restrictions, but still PHP's type conversion lets you abuse floating point precision.
`?param1=1.0000000000000000000000000000000000000000000000000001&param2=1.0000000000000000000000000000000000000000000000000000`

Flag: `X-MAS{s0_php_m4ny_skillz-69acb43810ed4c42}`
