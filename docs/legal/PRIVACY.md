# Privacy policy (template for operators of a klacks instance)

> **This is a template, not legal advice.** klacks is software you run
> yourself, and its authors operate no service and collect nothing. If you
> run a klacks instance for other people, or ship an app built on it, *you*
> are the operator. Adapt this text to your deployment, your other systems
> and your jurisdiction (for example GDPR or CCPA), and have it reviewed by
> a lawyer before you publish it. Replace every `[bracketed]` field.

**[Service name]** ("we") runs a messaging service built on klacks. This
policy describes what the messaging server stores and why. It was last
updated on **[date]**.

## End-to-end encryption

Messages are encrypted on your device before they are sent, and decrypted
only on the devices of the people you are messaging. The encryption uses
the X3DH key agreement, the Double Ratchet and, in groups, Sender Keys.
**Our server never receives the keys needed to read your messages, and
cannot read their content, attachments sent inside them, or their
headers.** We cannot hand over message content we cannot read.

## What the server stores

To deliver messages, the server keeps the following:

| Data | What it is | Why |
|---|---|---|
| Encrypted messages | The ciphertext and encrypted header of each message, with its room, sender's user and device identifiers, a message identifier, its position (sequence number) in the room and the time it was stored | To deliver messages, including to devices that were offline, and to let devices catch up |
| Rooms and membership | Each conversation's identifier, type (direct, group, space) and creation time; who is in it, with what role, since when | To decide who may send to and read from each conversation |
| Device keys | Each device's public identity key, signed prekey and a batch of one-time prekeys (public halves only) | So others can start encrypted conversations with your device; a one-time prekey is deleted once it is used |
| Membership change history | Who added or removed whom, in which room, and when (where the audit log is enabled) | Security and abuse investigation |
| Operational logs | User, device and connection identifiers, connection times, and error details | Running, securing and debugging the service |

User and device identifiers are opaque values issued by **[your identity
provider / you]**. The messaging server does not store names, email
addresses, phone numbers or contacts. **[If your wider service does, describe
that here or link to the policy that does.]**

The server does not record your IP address itself. **[Network equipment in
front of it, such as a load balancer or reverse proxy, may log IP addresses:
describe what yours does and for how long.]**

## What the server can infer (metadata)

Even without message content, the stored data shows who is in which
conversation, who sent a message and when, how often, and the size of each
encrypted message. We use this only to operate the service **[and for:
list any other purposes, or state there are none]**.

## Retention

By default klacks keeps encrypted messages and room data until they are
deleted by the operator; it does not expire them automatically. **[State
your retention period and how deletion works, for example: "We delete
encrypted messages after N days" or "when you delete your account".]**
Operational logs are kept for **[period]**.

## Sharing

We do not sell your data. We share it only with service providers that
host the service for us (**[list, for example your cloud provider]**), and
when we are legally required to. In that case we can provide only what is
listed above: we cannot provide message content.

## Your rights

**[Describe how people can access, export or delete their data, and how to
contact you, as your jurisdiction requires.]**

## Security

Data is stored in **[PostgreSQL and ScyllaDB hosted at: location]**.
**[Describe encryption at rest, TLS in transit, and access controls.]**

## Changes and contact

We will post changes to this policy here. Questions: **[contact]**.
