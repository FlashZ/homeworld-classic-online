---
id: 20
slug: "rebuilding-retail-won-with-ai"
title: "Rebuilding Retail WON for Homeworld, and Testing AI-Assisted Reverse Engineering for Real"
description: "How I rebuilt enough of Sierra's old WON backend to get retail Homeworld and Cataclysm online again, why the project became a genuine test of AI-assisted reverse engineering, and how long-form live testing is what really got it over the line."
pubDate: "2026-03-31"
author: "Nick Kerr-Bell"
category: "Open Source"
featured: true
readTime: 16
---

This project did not come together because I sat down, stared at some old code, asked AI a few clever questions, and got a working server out the other end.

It came together because I spent a lot of time doing the unglamorous part: testing, breaking, logging, patching, retesting, and repeating that loop until the server's behaviour finally matched what the original retail clients were actually expecting.

That matters, because one of the main reasons this project exists at all was to test something pretty specific: **how useful modern AI actually is for reverse engineering old software in a real-world setting**.

The answer, at least from this project, is not "AI solves reverse engineering now."

The answer is that AI can be extremely useful, but only when it is sitting inside a very tight feedback loop with real clients, real logs, real packet captures, real bugs, and a human being willing to throw away elegant theories that do not survive contact with reality.

That is what this project became.

---

### What I was trying to build

At its core, this project is an attempt to get the original retail **Homeworld** and **Homeworld: Cataclysm** online again using a clean-room, interoperable replacement for enough of Sierra's old WON backend to make the clients happy.

That means rebuilding the parts that matter to the retail games:

- authentication
- directory lookup
- factory / game launch flow
- routing / lobby / chat behaviour
- firewall probe behaviour
- client bootstrap through `NetTweak.script` and `kver.kp`
- retail-format CD key handling

It also means dealing with the reality that this was never just "server code." It is a whole system. The client bootstrap matters. The verifier key matters. Routing room behaviour matters. Timing matters. A lot of small details matter.

And because the original proprietary pieces are not all present, the only way to rebuild it properly is from the outside in:

- read the Homeworld client source where available
- read the known WON code where available
- inspect packet captures
- compare expected versus observed wire behaviour
- keep building until the clients stop complaining and start behaving normally

That is where the AI-assisted reverse engineering angle came in.

I was not trying to reproduce lost original server source. I do not have it, and that was never the point. The project was always about behavioural compatibility: treat the client and the surviving code like a black box with a few windows into it, then reconstruct enough of the surrounding infrastructure to make the real retail software behave correctly again.

That sounds straightforward when written cleanly in a paragraph. In practice it meant a lot of time moving between old C and C++ code, packet traces, Python code I was writing in the present, and then the very rude final arbiter: the actual game client doing something unexpected.

---

### Why this was a good AI test

A lot of AI discussion around reverse engineering is either too optimistic or too vague.

The overly optimistic version is that AI can somehow ingest a dead binary or an old codebase and reconstruct the entire system in one go.

The vague version is that AI is "useful for coding," which is true but not especially interesting.

What made this project valuable as a test is that it was neither of those things. It was a bounded but messy real-world problem with a lot of partial information:

- some surviving game source
- some surviving WON code
- missing proprietary pieces
- captured traffic
- retail clients that still had very strong opinions about how things should behave
- a live environment where incorrect assumptions turned into obvious failure very quickly

That kind of problem is where AI can either become a genuine force multiplier or a very efficient way of fooling yourself.

I wanted to find out which one it would be.

---

### The AI part was real, but it was not magic

A big part of this project has been me testing how far AI can actually help with reverse engineering.

Not in the hand-wavy way people talk about it online. I mean in the practical sense:

- can it help trace protocol structure faster?
- can it help connect client code to server behaviour?
- can it help turn packet captures into useful hypotheses?
- can it help refactor a growing compatibility layer without it turning into a complete mess?
- can it help me move faster without quietly pushing me off a cliff?

The answer was yes, with a very large asterisk.

AI was genuinely helpful at:

- compressing a lot of protocol and code context quickly
- identifying likely relationships between Titan/WON messages and client behaviour
- surfacing places in the old code where auth, directory, routing, and game launch connected
- generating scaffolding for tests, admin tooling, and refactors
- helping me keep momentum when the codebase started getting bigger and more complex

Where it absolutely did **not** replace real work was in validation.

It could suggest what a login flow probably meant. It could suggest what a routing room was probably doing. It could help map big- versus little-endian handling, byte layout, and message framing.

But the only thing that actually proved those ideas were right was getting the retail client to do the thing it was supposed to do.

That became the core lesson of the whole exercise.

The part I think is easiest to miss if you only look at the final code is how often the AI-generated or AI-assisted "likely explanation" was almost right rather than right. And "almost right" is a dangerous place to be with old clients. One field is wrong. One message is sent on the wrong step. One room flag is interpreted too broadly. One timeout is tuned for a lobby when it really belongs to a game flow. The result looks like progress for a while and then falls over exactly where the real client becomes strict.

That meant the actual useful workflow was never:

1. ask AI
2. accept answer
3. move on

It was much more like:

1. gather code and packet context
2. ask AI to help organise or interpret it
3. compare that interpretation to the source and the captures
4. implement a narrow hypothesis
5. run the real client
6. inspect what broke
7. adjust the hypothesis

That is still a meaningful win. It is just a very different kind of win than the fantasy version people sometimes imagine.

---

### The project only got real once the long testing started

The part I think is easiest to understate is how much of this project was shaped by long-form live testing.

There was a session in particular that really crystallised this for me. It started out as a deep research and protocol-tracing session, but it very quickly stopped being "study the old software" and turned into "keep pushing until the thing actually works under real use."

That session alone covered a huge amount of ground:

- checking the implementation against packet captures from Wireshark
- confirming that Auth1 and key handling were working
- discovering that auth was fine but directory flow was still failing
- getting the chat/lobby side to a usable state
- moving from one client to a second client on a laptop
- debugging why the second client would not connect over the network
- getting the first successful real game launch
- holding a game stable for several minutes
- confirming map downloads worked
- testing leave/rejoin behaviour
- hitting visibility bugs where a newly hosted game could not be seen by the second client
- realising better admin tooling was needed because the logs alone were not enough
- pushing the whole thing onto a VPS
- dealing with ports, DNS, firewall rules, Oracle security lists, tcpdump traces, and Docker
- finding stale lobby presence issues after a machine had been off for hours

That is not a side note. That is the project.

The reverse engineering gave me a direction.
The live testing is what made the direction honest.

What really changed for me during that stretch was the standard of proof. Before that, there is a temptation with this kind of project to think in terms of "the theory seems sound" or "the messages look close." Once you are actually running two clients, on different machines, over a local network and then over the internet, those standards stop being useful. Either the client authenticates, enters the lobby, sees the right thing, launches the game, returns correctly, and reconnects properly, or it does not.

That brutal clarity is what made the project better.

It also made the AI test better, because it meant the AI output was constantly being judged against something that could not be charmed or persuaded: actual old software behaving exactly as it always had.

---

### The first big hurdle: the client does not care how clever your theory is

One of the things old game software teaches you very quickly is that the client does not care whether your implementation is elegant, well-structured, or conceptually sound.

It only cares whether the behaviour matches.

That sounds obvious, but it has real consequences.

You can have a very convincing explanation for how auth should work, and still fail because one part of the handshake is packaged slightly wrong.
You can think the lobby flow is implemented correctly, and still be wrong because a room is being treated as a chat room when the client expects it to transition like a game.
You can be "close" on directory or routing behaviour and still get nowhere useful.

That is why this project ended up living in an iterative loop:

1. read code or packet captures
2. form a theory
3. implement the theory
4. run the real client
5. watch where it breaks
6. inspect logs, room state, or packet flow
7. patch it
8. do it again

AI helped in the middle of that loop. The loop itself is what mattered.

One of the more valuable things the project taught me is that reverse engineering old network software is often less about "discovering the grand design" and more about repeatedly trimming away wrong assumptions.

At the beginning, the system feels large and mysterious.
By the middle, it feels like a collection of specific stubborn behaviours.
By the end, what matters is not how complete your conceptual model is, but whether the remaining unknowns are small enough that the client no longer notices.

That is a very different emotional rhythm from ordinary greenfield development. It is slower, less elegant, and much more empirical.

---

### Packet captures and old code are useful, but neither tells the whole story

One of the interesting tensions in this project was that both the code and the captures were incomplete in different ways.

The Homeworld-side code tells you a lot about intent:

- what services the client thinks should exist
- what messages it sends
- what steps it expects to happen in what order
- where the game thinks it is entering auth, directory, factory, and routing flows

The WON-side code tells you a lot about message families, helper classes, and how the old ecosystem was structured.

Packet captures tell you what actually happened on the wire.

But none of those, by themselves, are enough.

The code can describe a path that you have not implemented correctly.
The capture can show a packet sequence without fully explaining the semantic reason for it.
The surviving WON code can reveal structures and message types without proving which subset Homeworld actually depended on in practice.

The really useful work happened in the overlap between them:

- find a relevant client codepath
- match it to a packet sequence
- compare that to what the current implementation is doing
- decide whether the gap is structural, timing-related, or just a missing detail

That is exactly the sort of place where AI can help a lot, because it is good at reducing search space and keeping a lot of related context in working memory. But again, it only helps if the final answer is checked against the running system.

---

### Homeworld and Cataclysm were close enough to be dangerous

Another big hurdle was that Homeworld and Cataclysm are similar enough to encourage shared infrastructure, but different enough to punish lazy assumptions.

The crypto, retail CD key format, and much of the broad Titan/WON shape are similar enough that one codebase absolutely makes sense.

But once I started doing prolonged live validation, the differences became impossible to ignore.

They showed up in areas like:

- valid version handling
- room naming and directory structure
- published versus unpublished room behaviour
- reconnect semantics
- post-game return-to-lobby behaviour
- account creation flow quirks
- dashboard interpretation of what counted as a live game

This is one of the reasons the project eventually grew proper product profiles instead of remaining a Homeworld-shaped implementation with Cataclysm bolted onto the side.

On paper they looked close.
Under live use, they taught me otherwise.

This was one of the places where I think the project got significantly better over time. Early on, the natural instinct is to view Cataclysm as "mostly Homeworld with a few differences." That is true in the shallow sense and dangerous in the operational sense. A lot of pain later came from exactly that sort of assumption: the codebase would be broadly right, but the moment a Cataclysm-specific path exercised reconnects, valid versions, room publication, or return-to-lobby behaviour, it exposed that "mostly" is not good enough.

That is why I now think the shared codebase was the right decision, but only alongside very clear product boundaries inside it.

---

### The installer became just as important as the backend

Another thing this project made very clear is that it is not enough to "have a server."

For these retail games, the client bootstrap path matters just as much as the backend implementation.

If the wrong host is being used, if `NetTweak.script` is wrong, if `kver.kp` is missing or mismatched, or if the registry/CD key path is wrong, you can have a perfectly decent backend and still get nowhere.

So the installer stopped being an afterthought and became part of the actual system.

That brought its own set of hurdles:

- auto-detecting the right game install
- letting people patch both Homeworld and Cataclysm cleanly
- handling users with multiple installs
- ensuring the client actually uses the patched path
- generating retail-format product-specific CD keys
- avoiding reuse of old shared keys from earlier installer builds

One of the more interesting bugs there was a false alarm that looked like broken random key generation. Some users were showing up with the same Homeworld CD key, which immediately looked like a serious problem.

The random generator itself turned out to be fine.
The real issue was subtler: old legacy shared installer keys were being preserved because the installer was treating them like ordinary user-owned existing keys.

That sort of thing happened repeatedly in this project. The first explanation was often the wrong one. The fix usually lived one level deeper than the symptom.

The installer also ended up being the point where the project became much more shareable. It is one thing for me to manually patch hosts, keys, and registry values on my own machines. It is another thing entirely to hand something to someone else and expect them to get a working result without already understanding the whole stack.

That is why I now think of the installer as part of the interoperability layer, not just a convenience wrapper around it.

---

### The admin dashboard exists because the logs were not enough

If this had stayed a pure reverse-engineering exercise, I probably would not have spent nearly as much time on the admin/dashboard side.

But once real people started connecting and testing, it became obvious that raw logs were not enough.

I needed to know things like:

- who is online right now?
- are they in the lobby or actually in a game?
- which product are they using?
- did the room behave like a lobby, a published game, or an unpublished live game room?
- was a disconnect voluntary, a reconnect hold, or a crash aftermath?
- was the dashboard's internal picture of the server actually matching what players were seeing?

That last one turned out to be especially important.

There were multiple moments where the server was technically doing something, but the dashboard was classifying it in a way that made debugging harder. A live match that did not show as a live game is not just a cosmetic issue. It creates doubt about whether the server and the operator are even looking at the same reality.

So the dashboard turned from a nice-to-have into part of the debugging process itself.

That is also where some of the biggest Homeworld-shaped assumptions got exposed once Cataclysm started running through the same infrastructure.

It is easy to think of admin tooling as something you build after the core system works. My experience here was almost the opposite. The better the dashboard got, the easier it became to notice what the core system still had wrong. Once rooms, products, reconnect holds, player states, game counts, and peer-data activity were visible in one place, the bugs stopped hiding in the ambiguity between "the client feels wrong" and "the logs seem fine."

In that sense, the dashboard was not merely operational tooling. It became instrumentation for the reverse-engineering process itself.

---

### The VPS move was a turning point

Getting the thing working locally was one milestone.
Getting it working across a real public network was another.

That move to the VPS forced a different class of problems to show up:

- host versus public IP confusion
- whether `NetTweak` was really being applied
- whether a second machine on a different network path could actually reach the gateway
- open ports versus actually reachable ports
- Docker versus Python deployment differences
- Oracle firewall/security-list weirdness
- tcpdump proving the traffic was arriving even when the client still looked broken

This was also where the project stopped being a purely local technical exercise and started becoming something that could actually support real external play testing.

That matters because it changed the standard of proof.

Once the server is on a VPS and people are joining from outside your local network, you stop asking "does it work on my machine?" and start asking "does it work in the messy, actual world?"

That is a much better test.

It is also a much harsher one.

The VPS phase also exposed how many layers have to cooperate before the game even reaches the interesting part:

- DNS or host configuration
- the bootstrap files on the client
- the gateway listener itself
- the backend listener behind it
- the VPS firewall
- the cloud network security list
- whatever mistakes you made in your own deployment instructions

That sounds basic, but it matters because public deployment is where a lot of elegant local assumptions go to die. If the project had stayed in the comfort zone of one machine or one LAN, I think it would have looked "more done" than it really was. The internet was less polite about the remaining flaws.

---

### A lot of the hardest bugs were not glamorous

Not every problem was some deep cryptographic or protocol revelation.

A lot of the hardest issues were exactly the kind of awkward, practical bugs that only show up after you have something almost-working:

- a second client not seeing a newly created game after one player left and rejoined
- stale users staying in the lobby long after a machine had been turned off
- reconnect logic that made sense for one game but not the other
- game visibility that looked wrong in the admin panel even when traffic clearly showed a match was active
- transitions back to the lobby behaving differently between Homeworld and Cataclysm

These are not glamorous bugs, but they are the bugs that determine whether people trust the system.

And again, this is where AI was useful but not sufficient.

It could help narrow possibilities. It could help interpret logs. It could help speed up instrumentation and code changes. But the actual truth of the bug only emerged because the bug was reproduced under real conditions.

I think this is one of the biggest differences between a project like this and a more ordinary software build. In a greenfield app, you can often rely on tests and internal logic to tell you whether a change is correct. In a compatibility project, a lot of the meaningful correctness lives outside your codebase. It lives in how an old client behaves, how users move through it, and whether the transitions feel right rather than merely possible.

That is why seemingly small bugs ended up consuming so much attention. They were often the exact places where "technically operating" still fell short of "behaving like the real thing."

---

### The weird old bugs were half the fun

One of the most enjoyable parts of the project, honestly, is that old software has personality.

Modern systems absolutely have bugs, but old games have bugs with texture.

Sometimes the bug was protocol-level. Sometimes it was a room-state issue. Sometimes it was a reconnect hold that made sense in one context and was completely wrong in another. And sometimes it was something wonderfully specific, like finally fixing the old Homeworld desync issue caused by shooting dust clouds with ion cannons.

Those details matter because they stop the whole thing from being just a dry networking exercise. The goal is not only to make a login screen and a list of rooms appear. The goal is to bring back the original retail experience in a way that respects all the awkward history wrapped up inside it.

That includes the parts that feel oddly specific and overfitted.
In fact, those parts are often exactly what tell you that you are finally dealing with the real software rather than an abstract model of it.

---

### Open-source reality changed some of the design

Another thing I ended up thinking about more than I expected was the tension between openness and operational control.

If I publish the code, anyone can run it.
If anyone can run it, the trust model becomes partly about keys, bootstrap files, and whether I want one public community network or many independent ones.

That affects things like:

- how client trust is anchored through `kver.kp`
- whether people can host their own instances cleanly
- how much of the README should be player-focused versus operator-focused
- what it means for this to be preservation work versus a single hosted service

This is one of the reasons the project ended up with stronger self-hosting notes, clearer key-generation paths, and a more deliberate split between user-facing bootstrap docs and deeper server/operator docs. Once the codebase became real enough to share, those questions stopped being hypothetical.

---

### So what did the project prove about AI-assisted reverse engineering?

For me, it proved something pretty specific.

AI is genuinely useful for reverse engineering when:

- you have real source fragments, packet captures, or protocol traces to reason about
- you can validate hypotheses quickly
- you can instrument the system easily
- you are willing to be skeptical of clean-sounding explanations

It becomes much less useful when:

- you treat its output as authoritative
- you do not have a good feedback loop
- you are tempted to accept "sounds plausible" as a substitute for "survived real testing"

That is probably the clearest lesson from this whole project.

The value was not that AI replaced the difficult work.
The value was that it accelerated the cycle of:

- understanding
- hypothesising
- implementing
- testing
- correcting

That is still a big deal.

But it is a very different claim from "AI rebuilt the old multiplayer server."

If I had to boil it down even further, I would say this:

AI was best at helping me move between layers.

It could help me go from client code to packet shape.
From packet shape to likely server behaviour.
From server behaviour to instrumentation.
From instrumentation to a narrower hypothesis.
From a rough implementation to a cleaner refactor once the rough implementation had proven itself.

That kind of layer-hopping is expensive mentally, and this project required a lot of it. That is where AI paid for itself.

---

### Where the project is now

At this point, the project is much further along than it was when it started as a rough attempt under `tools/won_oss_server`.

It now has:

- working retail bootstrap/install flow for Homeworld and Cataclysm
- product-aware backend and gateway code
- a unified installer for both games
- live admin visibility split by product
- Docker support and self-hosting paths
- an experimental shared-edge model for serving both games together
- better tests, better diagnostics, and better operational visibility than the early builds had

The important part, though, is not just the feature list.

It is that those features were forced into shape by prolonged contact with real users, real clients, and real multiplayer behaviour.

That is why I trust the project more now than I would have trusted an earlier version with fewer scars and cleaner theory.

I also trust the limits of it more clearly now.

That sounds strange, but it matters. A lot of the value in a project like this is knowing which parts are solid, which parts are experimental, and which parts only recently stopped being guesses. The long testing cycle was not just useful for getting things working. It was useful for making the remaining uncertainties smaller and more honest.

---

### Why I think the project matters

Part of this is simple preservation.

I like old games, and I hate the idea that working pieces of software history are allowed to die just because the original backend disappeared.

Part of it is that this was an unusually good technical problem:

- network protocol reconstruction
- interoperability
- installer/bootstrap work
- client/server debugging
- live operational testing
- long-tail bug cleanup

And part of it is that it gave me a practical way to test whether AI-assisted reverse engineering could hold up under real conditions rather than demos.

I think the answer is yes, but only if the human using it is willing to stay grounded in evidence.

This project did not succeed because AI had a magic understanding of old software.

It succeeded because AI was used as part of a stubborn, evidence-driven loop that kept going until the original games actually worked.

That, more than anything else, is what this project has been proving.

And for me, that is probably the most satisfying outcome of the whole thing. Not just that the original retail Homeworld games can speak to a modern replacement backend again, but that the path to getting there says something genuinely useful about software preservation, interoperability, and how AI can be used well without pretending it is doing magic.
