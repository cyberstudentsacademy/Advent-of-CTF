# Disoriented Santa

- Published: 12/13/2024 (#13/25 in event)
- Category: OSINT
- Points: 100
- Author: GodderE2D

Sorry that we woke you up at this hour, but Santa is missing. We suspect the K.U.N.A.L Secret Society kidnapped Santa
when he was flying over Europe while scoping out for some children.

Thankfully, Santa was equipped with a state-of-the-art GPS tracker circa 2008. Anyways, it gave us these clues:

- Santa is trapped in a **history museum**.
- The museum charges **3 EUR** for entry.
- There is a **library** within **1 km** of the museum.

Can you find the coordinates of the museum? The flag is in the format `csd{latitude,longitude}`, where each number is
**rounded** (not truncated) to 3 decimal places. Numbers within an error of ±0.001 are accepted.

For example, a flag could be `csd{11.533,-125.396}`.

## Hints

**Hint 1:**

Open-source maps like OpenStreetMap contain useful information related to businesses and other places. You can query
these maps using tools like [Overpass Turbo](https://overpass-turbo.eu/) to analyze these data given a filter you
define.

**Hint 2:**

[Overpass Turbo](https://overpass-turbo.eu/) supports filtering by
[OpenStreetMap tags](https://wiki.openstreetmap.org/wiki/Tags). Some tags may be useful to this challenge, such as
`tourism` and `charge`.

## Write-up

<details>
<summary>Reveal write-up</summary>

The briefing gave us 3 clues to use. The challenge of this CTF is finding the right tool to use. The right tool to use
was [overpass turbo](https://overpass-turbo.eu/). Open overpass turbo and put this query in:

```
[out:json][timeout:60];

(
  node["tourism"="museum"]["museum"="history"]["fee"="yes"]["charge"="3 EUR"](36.0,-11.0,71.0,40.0);
  way["tourism"="museum"]["museum"="history"]["fee"="yes"]["charge"="3 EUR"](36.0,-11.0,71.0,40.0);
  relation["tourism"="museum"]["museum"="history"]["fee"="yes"]["charge"="3 EUR"](36.0,-11.0,71.0,40.0);
)->.museums;

node["amenity"="library"](around.museums:1000) ->.libraries;

node.museums(around.libraries:1000);
out center;
```

After running this we should only get 1 result.

Flag: `csd{48.205, 7.365}`

</details>

Write-up by Dharneesh5555
