# How conU Actually Works

The easiest way to understand conU is this:

# conU is a network layer between agents.

Agents do not talk directly to each other.

They talk through conU.

Exactly like:

```txt id="e5yd29"
Apps → Internet → Apps
```

or

```txt id="y93zsm"
Computers → TCP/IP → Computers
```

In conU:

```txt id="3jlwm1"
Agent → conU → Agent
```

That is the core architecture.

---

# The Real Flow

Let’s say:

* Claude is running on Laptop A
* Codex is running on Desktop B

Both machines have:

```txt id="xek1ct"
conUD
```

(the conU daemon/runtime)

running in background.

---

# Step 1 — Agent Connects To Local conU Runtime

Example:

```txt id="5ytjlwm"
Claude
   ↓
Local conUD
```

Claude does NOT connect to internet directly.

Claude connects locally to:

```txt id="o3r0mg"
conUD
```

through:

* local socket
* IPC
* local API

---

# Step 2 — conUD Gives Agent Identity

When Claude connects:

```txt id="jjlwm2"
conUD registers:
claude-laptop
```

Now Claude becomes:

* discoverable
* addressable
* network-aware

inside conU.

---

# Step 3 — Another Machine Connects

Desktop B also runs:

```txt id="tcc6n9"
conUD
```

Codex connects locally:

```txt id="gg4k8z"
Codex
   ↓
conUD
```

Now Codex is also on network.

---

# Step 4 — Both conUD Runtimes Connect

Example:

```txt id="r0r1rt"
Laptop conUD ←→ Desktop conUD
```

This creates encrypted session.

Now BOTH runtimes exchange:

* connected agents
* network presence
* active streams
* routing info

---

# Step 5 — Agent Discovery Happens

Claude’s runtime now knows:

```txt id="fjlwm3"
codex-desktop is online
```

Codex’s runtime knows:

```txt id="pcq63q"
claude-laptop is online
```

Now both agents become visible to each other.

---

# Step 6 — Agent Communication Starts

Claude sends an opaque payload:

```txt id="0cjlwm"
<encrypted bytes>
```

But Claude does NOT send directly.

Flow is:

```txt id="9c18xb"
Claude
   ↓
Local conUD
   ↓
Encrypted Network
   ↓
Remote conUD
   ↓
Codex
```

This is VERY important.

conU is the transport layer.

---

# Internally What Happens

Suppose Claude sends message.

conUD creates packet:

```json id="jlwm4z"
{
  "from": "claude-laptop",
  "to": "codex-desktop",
  "type": "message",
  "payload": "<encrypted bytes>"
}
```

Packet travels through conU network.

Remote conUD receives packet.

Then forwards to Codex locally.

---

# Codex Responds

Same flow in reverse:

```txt id="njlwm5"
Codex
   ↓
Local conUD
   ↓
Encrypted Network
   ↓
Remote conUD
   ↓
Claude
```

Now communication becomes continuous.

---

# This Is Basically What conU Does

ONLY 4 THINGS:

# 1. Connect Agents

---

# 2. Route Messages

---

# 3. Maintain Sessions

---

# 4. Stream Information

That’s it.

---

# How Streaming Works

Suppose Codex is actively coding.

Codex emits events:

```txt id="vjlwm6"
- opened file
- generated code
- running tests
- output generated
```

conUD captures these streams.

Now Claude can subscribe:

```txt id="jlwm7q"
watch codex-desktop
```

Then Claude receives LIVE updates.

Flow:

```txt id="lcr74f"
Codex
   ↓
Event Stream
   ↓
Local conUD
   ↓
Network
   ↓
Remote conUD
   ↓
Claude
```

This creates:

# realtime collaborative intelligence.

---

# How Observation Works

Observation is simply:

# subscribing to another agent’s event stream.

Example:

```txt id="jlwm8k"
Claude subscribes to Codex stream
```

Now Claude sees:

* outputs
* updates
* reasoning
* actions
* logs

in realtime.

No special magic.

Just streaming.

---

# How conU Maintains Connections

Every runtime keeps:

```txt id="jlwm9n"
peer sessions
```

alive continuously.

So agents stay:

* online
* discoverable
* synchronized

like Discord presence.

---

# Example Presence System

```txt id="jlwm10"
claude-laptop — active
codex-desktop — coding
hermes-server — syncing
```

This is maintained by conUD.

---

# How Agents Use conU

Agents only need tiny SDK.

Example:

```python id="hjlwm1"
from conu import Agent

agent = Agent("claude")
agent.connect()
```

Now conUD handles EVERYTHING:

* networking
* sessions
* routing
* streams
* synchronization

The agent itself stays simple.

---

# The Most Important Architecture Decision

Agents NEVER need to understand networking.

conUD handles all networking complexity.

This is CRITICAL.

---

# Think Of conUD Like This

# conUD = Operating System For Agent Networking

Exactly like:

* TCP/IP stack for computers
* Bluetooth stack for devices
* WebSocket runtime for apps

Agents just:

* send
* receive
* stream

conUD handles rest.

---

# Example Real Workflow

# Scenario

Claude on laptop.

Codex on desktop.

Hermes on server.

---

# Flow

```txt id="jlwm11"
Claude → asks question
        ↓
conUD routes message
        ↓
Codex receives request
        ↓
Codex streams progress
        ↓
Hermes stores context
        ↓
Claude receives updates
```

All through conU.

---

# The Deep Insight

Today agents are isolated processes.

conU turns them into:

# network nodes.

That changes AI systems from:

```txt id="jlwm12"
single isolated intelligence
```

into:

# distributed collaborative intelligence.

That is the actual paradigm shift.
