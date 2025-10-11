# Understanding Episodic and Semantic Memory in the AI Agent

## 🧠 Memory Types Explained

Your enhanced AI agent uses **two types of memory** inspired by human cognition:

---

## 1. 📖 Episodic Memory (Short-term, Conversation-based)

**What it is:** 
- Like your personal memory of events and experiences
- Stores the **actual conversation** - what was said and when
- Time-based and sequential

**What it stores:**
- Each message in the conversation
- Who said it (user or assistant)
- When it was said (timestamp)
- How the customer felt (sentiment)

**Example:**
```
[Conversation History - Episodic Memory]
2025-10-02 10:30 AM | User: "Where is my order?"
2025-10-02 10:31 AM | Agent: "Let me check that for you..."
2025-10-02 10:32 AM | User: "Thanks!"
                      Sentiment: positive
```

**Database Table:** `conversations`
```sql
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    customer_id TEXT,
    timestamp TEXT,
    role TEXT,              -- 'user' or 'assistant'
    content TEXT,           -- the actual message
    sentiment TEXT,         -- 'positive', 'negative', 'neutral'
    metadata TEXT           -- extra info (JSON)
)
```

**How it's used:**
- Agent recalls recent conversation to maintain context
- "You mentioned earlier that..."
- Prevents repeating questions already answered
- Tracks sentiment changes during conversation

---

## 2. 🏛️ Semantic Memory (Long-term, Knowledge-based)

**What it is:**
- Like your general knowledge about people and facts
- Stores **what we know about the customer**
- Not tied to specific conversations
- Accumulated over time

**What it stores:**
- Customer profile (name, email)
- Loyalty tier (Silver, Gold, Platinum)
- Preferences (communication style, language)
- Overall sentiment patterns
- Summary of their history
- Total number of interactions

**Example:**
```
[Customer Profile - Semantic Memory]
Name: Sarah Johnson
Email: sarah.j@email.com
Loyalty Tier: Gold
Total Orders: 12
Lifetime Value: $2,450
Sentiment History: [positive, positive, neutral]
Summary: "Tech-savvy customer. Prefers quick responses. 
         Had one delivery issue (resolved). Very satisfied overall."
```

**Database Table:** `customer_context`
```sql
CREATE TABLE customer_context (
    customer_id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    loyalty_tier TEXT,           -- Silver/Gold/Platinum
    preferences TEXT,             -- JSON: communication prefs
    sentiment_history TEXT,       -- JSON: [positive, neutral, ...]
    history_summary TEXT,         -- Text summary of past
    last_interaction TEXT,        -- Last contact date
    total_interactions INTEGER    -- Count of all interactions
)
```

**How it's used:**
- Personalization: "Hi Sarah! Welcome back!"
- Context: "As a Gold member, you get..."
- Pattern recognition: "You usually prefer email contact"
- Service quality: "I see you had an issue last month - how is everything now?"

---

## 🔄 How They Work Together

### Example Scenario:

**First Interaction (Building Semantic Memory):**
```
Customer: "Hi, I'm Sarah. I want to buy a TV."

Agent actions:
1. Creates episodic memory (this conversation)
2. Creates/updates semantic memory (name: Sarah)
3. Responds warmly
```

**Later Interaction (Using Both Memories):**
```
Customer: "Where's my order?"

Agent actions:
1. Recalls SEMANTIC memory: "This is Sarah, Gold member, likes quick answers"
2. Recalls EPISODIC memory: "She ordered a TV 3 days ago in our last chat"
3. Responds: "Hi Sarah! Let me check your TV order right away..."
```

---

## 💡 Real-World Analogy

Think of it like meeting someone at a coffee shop:

**Episodic Memory** = "What we talked about today"
- "You just told me you're looking for a TV"
- "Five minutes ago you asked about shipping"
- "Earlier you seemed frustrated, but now you're happy"

**Semantic Memory** = "What I know about you"
- "You're Sarah, a regular customer"
- "You always order electronics"
- "You prefer email over phone calls"
- "You're a Gold member"

---

## 🎯 Why This Matters for Customer Support

### 1. **Continuity Across Sessions**
```
Day 1: "I ordered a TV"
Day 5: Customer returns with "Any updates?"
Agent: "Hi Sarah! Your TV is arriving tomorrow!" 
       (Without customer re-explaining everything)
```

### 2. **Personalization**
```
Agent knows:
- Your name
- Your loyalty tier
- Your preferences
- Your history

Response: "Hi Sarah! As a Gold member, you get free shipping on this order!"
```

### 3. **Sentiment Tracking**
```
Conversation 1: frustrated → satisfied
Conversation 2: positive
Conversation 3: neutral

Agent knows: "This customer is usually happy, but had one bad experience"
Service approach: "Extra careful with this order"
```

### 4. **Context Preservation**
```
Customer: "It"
Agent: "Your SmartHome Hub? Yes, the firmware update is coming next week."
(Agent remembers from context what "it" refers to)
```

---

## 🔧 Technical Implementation

### Episodic Memory Flow:
```python
# 1. Customer sends message
customer_message = "Where is my order?"

# 2. Save to episodic memory
memory.save_message(
    customer_id="CUST-1001",
    role="user",
    content="Where is my order?",
    sentiment="neutral"  # Auto-detected
)

# 3. Retrieve recent history for context
history = memory.get_conversation_history("CUST-1001", limit=10)

# 4. Agent uses history to understand context
# 5. Agent responds
# 6. Save agent response to episodic memory
memory.save_message(
    customer_id="CUST-1001",
    role="assistant",
    content="Your order is arriving tomorrow!",
    sentiment="helpful"
)
```

### Semantic Memory Flow:
```python
# 1. First time customer
profile = memory.get_customer_context("CUST-1001")
# Returns None (customer unknown)

# 2. Create customer profile
memory.update_customer_context(
    customer_id="CUST-1001",
    name="Sarah Johnson",
    loyalty_tier="Gold",
    preferences=json.dumps({"communication": "email"}),
    sentiment_history=json.dumps(["positive"])
)

# 3. Future interactions automatically recall this
profile = memory.get_customer_context("CUST-1001")
# Returns: {name: "Sarah Johnson", loyalty_tier: "Gold", ...}

# 4. Agent personalizes response
# "Hi Sarah! As a Gold member..."
```

---

## 📊 Memory Hierarchy

```
┌─────────────────────────────────────┐
│   CURRENT CONVERSATION (RAM)        │  ← Active processing
│   - Current message                 │
│   - Agent thinking                  │
└─────────────────────────────────────┘
            ↓ ↑
┌─────────────────────────────────────┐
│   EPISODIC MEMORY (Database)        │  ← Recent conversations
│   - Last 10 messages                │
│   - This session + recent sessions  │
│   - Time-ordered                    │
└─────────────────────────────────────┘
            ↓ ↑
┌─────────────────────────────────────┐
│   SEMANTIC MEMORY (Database)        │  ← Long-term knowledge
│   - Customer profile                │
│   - Aggregated patterns             │
│   - Summary information             │
└─────────────────────────────────────┘
            ↓ ↑
┌─────────────────────────────────────┐
│   SUPPORT HISTORY (Database)        │  ← Historical records
│   - Past issues                     │
│   - Resolutions                     │
│   - Agent notes                     │
└─────────────────────────────────────┘
```

---

## 🎬 Complete Example

### Customer Journey:

**Interaction 1 (Sept 15):**
```
Customer: "I need a TV for gaming"
Agent: "Great! I recommend the UltraView 4K..."
Customer: "Perfect, I'll order it"

Episodic Memory Created:
- 3 messages stored
- Sentiment: positive

Semantic Memory Created:
- Name: (not yet known)
- Interest: Gaming, TVs
- First interaction: Sept 15
- Sentiment: positive
```

**Interaction 2 (Sept 20):**
```
Customer: "Where is my order?"
Agent: "Hi! Let me check your TV order..."

Episodic Memory:
- Agent recalls from Sept 15 conversation
- "You ordered the UltraView TV"

Semantic Memory Updated:
- Total interactions: 2
- Pattern: Asks about orders
- Sentiment history: [positive, neutral]
```

**Interaction 3 (Oct 2):**
```
Customer: "The TV has an HDMI issue"
Agent: "I see you purchased the UltraView TV. 
       I also notice there's a known HDMI issue with that model.
       Let me help you fix it..."

Uses ALL memories:
- Episodic: Recent conversations
- Semantic: Customer profile, purchase history
- Support History: Previous interactions
- RAG: Known issues database
```

---

## 🛠️ How to Fix Your Current Issue

Run this command to update your database:

```powershell
python migrate_db.py
```

Select option 1 to migrate (keeps existing data) or option 2 for fresh start.

---

## ✅ Benefits Summary

| Feature | Without Memory | With Episodic + Semantic |
|---------|---------------|-------------------------|
| Personalization | "Hello" | "Hi Sarah!" |
| Context | Customer re-explains | Agent remembers |
| Consistency | Random responses | Consistent experience |
| Efficiency | Repetitive questions | Quick resolution |
| Loyalty | Transactional | Relationship-based |

---

## 🎯 Yes, I Added Both!

✅ **Episodic Memory** - Full conversation history with sentiment  
✅ **Semantic Memory** - Customer profiles and patterns  
✅ **Support History** - Past issues and resolutions  
✅ **Sentiment Tracking** - How customers feel over time  
✅ **RAG System** - Policy and product knowledge  

All working together to create a truly intelligent customer support agent! 🚀
