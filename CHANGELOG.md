# Changelog

All notable changes to the open-source CONTEXA core are documented in this file.

The format is based on Keep a Changelog and the project follows semantic versioning in principle.

## [Unreleased]

### Security

- A confirmation is no longer asked for an agent whose tenant, user, agent or delegation identifier is longer than a confirmation keeps (255, 255, 255 and 64 characters): the database refused such a confirmation with an error while memory kept it. An identifier is never cut, since a cut one names another delegation or agent and a report would stop the wrong one, so both stores now ask no one: the gate answers `413 AGENT_CONFIRMATION_UNBINDABLE`, the agent's own ask 400.
- An agent's ask for a confirmation whose target carries, as written, a space, a control character, a line break or a character that turns the text around (no request line carries one) is answered 400, so an agent cannot write a sentence of its own where the person reads the request. Written escaped, the same characters are asked as before.
- A request of an agent whose path and query are longer than a confirmation keeps (2048 characters, as a person reads them) no longer asks its accountable person to confirm a request they would read cut: it is refused with `413 AGENT_CONFIRMATION_UNBINDABLE`, as a body too large to bind is. Decided in the request itself, it gets the plain answer to a CHALLENGE and asks no one either.
- What an agent asks a person to confirm keeps no secret of its target: a value that opens something is masked as it is when the gate stops a request, the path the application serves is shown masked too, and a target that would not fit once masked is refused.
- An agent's ask for a confirmation now names a standard HTTP method and a target of at most 2048 characters, else it is answered 400. A longer target was cut where it is kept, so the person approved a request they could not read in full, and a method past 16 characters was kept cut in the database and whole in memory; both stores now keep a value past its column alike.
- A person confirming an agent's request now also reads the path the application will serve when the agent spelled another (`/api/%65xport/x` is served as `/api/export/x`), on the confirmation page, the list and the mail. The target the agent sent is shown as before; what the decoding brings out that cannot be seen, breaks the line or turns the text around, a space included, stays escaped.
- The mail of a confirmation an agent asks for itself (`POST /contexa/api/agent-confirmations`) now links to `contexa.security.zerotrust.agent.confirmation-link-base-url` and the application's context path, as the mail of a request Contexa stopped does; it was a bare path. Neither link ever takes the host the agent sent, so without that setting the link stays a path: set it for the mail to open.
- The admin API of delegations no longer lists delegations to an agent holding an administrator's token (403), as the person's own delegation API lists none to it.
- **An agent holding an administrator's token no longer writes or takes back a person's delegation.** The admin API of delegations (`/contexa/admin/api/agent-delegations`) and the console's revocation (`/contexa/admin/agents/delegations/revoke`) now answer 403 to a request the bridge reads as an agent's, as the person's own delegation API already did. An administrator's own requests, and an integration whose client is no agent, work as before.
- **A value an application keeps in the session no longer moves a person's request to an agent.** The session channel of
  the delegation read every session attribute and took any that named an agent: a map of request values with `agentId`
  and `delegated` moved a person's request to `<user>::agent::<agent id>`, past a CHALLENGE on the person, and a bean of
  the domain that only names an agent sent the person to an agent's confirmation instead of the step-up. The channel now
  reads `contexa.bridge.delegation.session.attribute` and the names in
  `contexa.bridge.delegation.session.attribute-candidates`, which is empty by default, and `auto-discover` is off by
  default. **Check:** an application that keeps its agents' delegation in the session names that attribute in
  `contexa.bridge.delegation.session.attribute`. Setting `auto-discover` to `true` reads every attribute again, and the
  start says so at INFO.
- **A value an application keeps in the session no longer adds to what the decisions read of a user's authorization.**
  The session channel of the authorization read every session attribute and took the one that looked most like an
  authorization: a map of request values with `roles=ROLE_ADMIN`, `privileged=true` or `effect=ALLOW` added that role,
  privilege or verdict to the authorization evidence of the request, which the decisions read. The channel now reads
  `contexa.bridge.authorization.session.attribute` and the names in
  `contexa.bridge.authorization.session.attribute-candidates`, which is empty by default, and `auto-discover` is off by
  default, as for the delegation. **Check:** an application that keeps the user's roles or its authorization verdicts in
  the session, under a name of its own or one of the former candidate names (`currentUser`, `authenticatedUser`,
  `sessionUser`, `userSession`, `principal`, `user`, `securityUser`, `authenticatedPrincipal`), names that attribute in
  `contexa.bridge.authorization.session.attribute`. Setting `auto-discover` to `true` reads every attribute again, and the
  start says so at INFO.
- **A first passkey is no longer registered on the strength of an MFA the application's principal only states.** Before
  a first passkey the step-up confirms the user, with a code mailed to the address on record or the application's own MFA
  sign-in moments before. That sign-in was read from the principal by the name of a value (`mfa`, `mfaVerified`, ...) and
  the time of the sign-in, so where a principal always carries `mfa=true` a password alone registered a passkey, which
  then answered CHALLENGEs. The application's sign-in now confirms the user for a passkey only when
  `contexa.bridge.step-up.reauthentication-url` is set, as for a CHALLENGE; elsewhere the mailed code does. **Check:** an
  application whose users registered their first passkey right after its own MFA sign-in sets
  `contexa.bridge.step-up.reauthentication-url`; without it a user whose copy has no real address registers no passkey,
  and the step-up page says to contact an administrator.
- **The application's own sign-in answers a CHALLENGE only where the application named its re-authentication.** A
  completed MFA was read from the principal by the name of a value (`mfa`, `mfaVerified`, ...) and the time of the
  sign-in, so a principal that always carries `mfa=true` released a CHALLENGE with a password sign-in alone. The
  application's sign-in now answers a CHALLENGE only when `contexa.bridge.step-up.reauthentication-url` is set; elsewhere
  Contexa's step-up does, by a mailed code or a passkey, and a user whose copy has no real address and no passkey finds
  no factor on the step-up page. **Check:** an application whose own MFA re-authentication released CHALLENGEs sets
  `contexa.bridge.step-up.reauthentication-url` to where it re-authenticates, or tells Contexa its users' addresses with a
  `BridgeUserEmailProvider`.
- **An address changed on the application's profile no longer gets the step-up's code.** The copy of a user took every
  address the application showed, so whoever held a session could change the profile's address and receive the code
  meant to stop them. A copy that holds a real address now keeps it: another address the application shows waits
  (`ctxa_bridge_user_profile.pending_email`) and takes its place once the user enters a code mailed to the address on
  record or answers with a passkey. The first real address of a copy that had a made-up one goes in at once, as before,
  and an address an administrator enters on the user's page of the console now stands. The column is added to an
  existing database at the next start. **Check:** a user who changed the address and can read neither the old mailbox
  nor answer with a passkey gets codes at the new address once an administrator enters it in the console.
- A value in a CSV export that a spreadsheet would run as a formula now stays text: users write the names and browsers in those files, and an administrator opens them. A cell that starts with `=`, `+`, `-` or `@` and is no plain number gets a leading quote.
- **The admin console shows a stored name as text, never as script.** A role, permission, user or policy name with a quote
  could end a click handler or an attribute in the policy center, the access center, the policy details, the delete dialog
  and the role hierarchy screen; names now reach handlers through data attributes and are escaped wherever they meet markup,
  the hierarchy diagram draws in strict mode with text labels, and a menu icon that opens with a tag has to be a plain SVG
  drawing of shapes: anything else is refused on save and shown as no icon. **Check:** a custom menu icon with other SVG
  elements, such as `g` or `text`, is no longer drawn; use a CSS class or a drawing of paths and basic shapes.
- **The sign-in pages write what the server answers as text.** The default form and REST sign-in pages and the shipped
  `contexa-login-page.js` put a sign-in message, an error or a support contact into the page as markup; they now write it
  as text, keeping the line break before the contact.
- **A menu address is a path inside the application.** The side menu links every administrator to the address of each
  menu, which took any value, `javascript:` and other sites included. Saving now refuses anything but a path that opens
  with a single `/`, and a stored address of another form is drawn with no link. **Check:** a custom menu that pointed to
  another site keeps its address on the menu screen but loses its link in the side menu until it is changed to a path.
- A role hierarchy whose diagram cannot be drawn lists its relations in the confirm dialog instead of stopping on a script
  error, and a policy version snapshot that fails to load says so.
- A one-time code asked for a name with no account leaves nothing in the log, and the mail shows a name as text, never as markup.
- **A sign-in by code no longer mails any address a stranger types.** Before a sign-in the name of a code request is what
  the form says, and a name of no account was mailed as an address: with `.ott()` anybody could have your mail server send a
  code, and the name itself in the text of the mail, to any mailbox. A code now goes to the address on record, or to the name
  of an account of the store the sign-in reads, the application's own included, so an application whose users sign in with
  their address goes on as before. Any other name is answered exactly as a mailed one, and nothing is made or sent. A store
  that cannot answer sends nothing and says so at ERROR. Such a code could sign in to nothing, so no working sign-in changes.
- **A risk signal that ends sessions now ends the tokens too.** A session revoked, a credential compromised and an account
  disabled or purged, sent by your identity provider, signed the subject out of its sessions and left its tokens running: a
  token client went on until the access token ran out, and then renewed it with the refresh token. These events now end the
  subject's access and refresh tokens as well, those an agent's client got for the subject by token exchange included, as a
  new password does. A restriction in force stays. A store that is down fails no event: what could not be ended keeps
  running and the log says so at ERROR.
- **A client named like a person no longer gets the person's rights.** A client's own token has the client's ID as its
  subject, and an account of that name was looked up first: a client registered as `alice` authenticated with everything
  the person `alice` holds, without being an approved agent or a listed service client. A client's own token now reads no
  account: it carries its scopes when the client is an approved agent or in `contexa.auth.oauth2.service-client-ids`, and is
  refused otherwise. Registering an agent's client under the name of an existing account is refused too. **Check:** a client
  that relied on an account of its own name gets its scopes only: give the scopes it needs to the client. A person named
  exactly as `contexa.auth.oauth2.client-id` can no longer sign in with a token, as that token now reads as the internal
  client's.
- **The refresh entry point no longer hands out what another client was issued.** `/api/refresh` asks for no client
  authentication, and a still valid access token never reached the token endpoint, which is what refuses a token of another
  client: whoever held a refresh token of an application you registered yourself got that application's access token back
  without its secret. The entry point now renews only what Contexa's internal client was issued, and answers any other token
  as one that is not there. That application goes on renewing its tokens at `/oauth2/token` with its secret.
- **A blocked address no longer locks an account through the password page.** `POST /contexa/password-change` refused a
  blocked address but still counted the attempt against the account it named, the right password too, so that address went
  on locking its owner out where a sign-in would have counted nothing. The attempt is now refused as before and counted
  against nobody.
- **The ALLOW of one sensitive record no longer answers the next one named in the query.** An agent's ALLOW answers one
  sensitive resource, and a resource was its path: after `GET /api/customers?id=1` an asynchronous `@Protectable` method
  answered `?id=2`, `?id=3` and on, up to the request limit, without a decision. For a sensitive resource the query now
  tells one resource from another, so each other query is decided again. The event carries a reference of the query
  (`queryReference`) that holds none of its values and reads differently in another process. **Check:** the pages of a
  sensitive list are now decided one by one, a model call each. A general resource stays its path: its queries count as
  one resource, up to the request limit.
- **An agent's asks for a confirmation now count against its call limits.** `POST /contexa/api/agent-confirmations` stayed
  out of the gate so that an agent can follow its confirmation, so one token could mail its accountable person once for
  every target it made up, without end. An ask now counts as any call of the agent does: past
  `contexa.security.zerotrust.agent.call-limit.*` it gets the gate's `429 AGENT_CALL_LIMIT` with `Retry-After`, nothing is
  kept and nobody is told. Polling a confirmation is not counted. The limit is that of calls, 120 a minute for a delegation
  by default, and an agent within it can still ask that often. A reason the agent wrote now reaches the mail after
  Contexa's own words and marked as the agent's, as the confirmation page shows it: it read as part of Contexa's sentence.
- **An agent no longer writes a delegation in the person's name.** The delegation API told an agent by the `act` claim, a
  client's own token and an agent's account. A token exchange without an `actor_token` is issued in the person's name with
  no `act`, so the agent it went to passed as the person at `/contexa/api/agent-delegations` and could give itself a
  delegation, read the person's and revoke them. The same went for a token of another authorization server that names
  the agent in `azp`, `agent_id` or a delegation marker. The API now answers `403` to whatever the bridge reads as an
  agent's request, as the confirmation pages do. Token exchange is off by default.
- **An agent narrowed to reading no longer writes through a path that sounds like reading.** The operation of a request was
  read from the words of its path before its method, and from the path as it was sent: `DELETE /api/lists/7` and
  `POST /api/search/x` passed as reads, and `GET /api/%65xport/x` reached the export as one. The words of a path, read as
  the application routes it, may now make a request graver than its method, never lighter: only `GET`, `HEAD` and `OPTIONS`
  read, and a word that says writing leaves a `DELETE` a deletion. The ALLOW of a read no longer answers these requests at
  an asynchronous `@Protectable` method either, unless the host declared the action or the method's name states it, and
  they no longer count as reads for `contexa.security.zerotrust.agent.flight.pass-families`. **Check:** a read served over
  `POST`, such as a search, is now a write: while an agent is narrowed it gets `403 AGENT_SCOPE_NARROWED` until the period
  ends or its accountable person confirms that request.
- **A blocked console session only reads.** The block list stays open to a console session under a BLOCK, and from there it
  could lift the BLOCK of anyone else, delete a record, release a CHALLENGE, and stop and resume the agents. It now reads
  the lists, its pages offer it nothing to change, and each of those is a 403 that stays in the audit, also after it passed
  a verification. Its own BLOCK is lifted as before: by another administrator, or by the session itself after it verifies at
  `/contexa/admin/blacklist/step-up`. Other administrators work as they did, and under SHADOW, OBSERVE or DISABLED a stored
  BLOCK stops nothing here either.
- **Killing the application no longer takes its decisions away.** A Kafka event was acknowledged the moment it was taken in,
  so everything still in analysis was lost with the process, and whoever could bring the application down escaped the decision
  on what they had just done. What is committed of a partition now stays below its first event the analysis is not done with.
  The consumer reads on as before, without a pause, and a node that dies leaves those events to be delivered again and decided
  by the next one; one decided already costs no second model call, so more may be delivered again than was lost. An event whose
  analysis does not end within the budget of one request (`event-timeout-ms` for each retry, and the margin) stops holding the
  commit and is reported. The standalone mode has no broker to deliver anything again: what it holds in memory dies with it.
- **An event left behind by a restarted container is decided.** An analysis cut short kept its claim for 30 minutes unless the
  process came back on the same host under another PID, and the event delivered again was dropped after retries spent in a
  moment. A process now says in Redis that it lives, every 5 seconds, and its claims pass to the next one within 15 seconds of
  its last word, whatever the host name and the PID. Tries on an event another owner holds are spread over half a minute.
- **A wrong password at the application now reaches the decision.** Under `HOST_OWNED` Contexa heard nothing of a failed
  sign-in, so the decision on the sign-in after it, and on the calls after that, read no failure. Contexa now listens to
  Spring Security's failure events and keeps a failure for the decisions alone: neither the lock of an account nor the limit
  of an address counts it, and the application's authentication is only read. An authentication manager that publishes no
  events, such as a `ProviderManager` built by hand, leaves the count unknown, and the prompt says so instead of zero. What
  a store keeps of failed sign-ins now has limits, the same in memory and in Redis: 10,000 names and addresses, the latest
  200 failures of each, names of up to 256 characters, all gone with their window. Past the first limit the keys written
  the longest ago go, and for a window a name without a record reads as unknown, not as no failures. Every spelling of a
  name counts as one person.
- **A sign-in after a run of wrong passwords no longer reads as any other sign-in.** Under `HOST_OWNED` the model decided the
  application's sign-in without what a protected call of the same request tells it: the signals the application states on
  the request, the authorities of the account, the failures on record and the bridge's stamps. A sign-in now carries all of
  them, through the same code as a protected call, and its decision is bound to the session the client presents next.
  `ZeroTrustEventPublisher.publishAuthenticationSuccess` now takes the authentication and the request. A sign-in stays out
  of what a role's usual work is compared with and learned from: the POST of a form is no work of the role.
- **A sign-in no longer wipes the failures of its address.** A password that was right took the address's count back, so
  whoever held one account of their own could try any number of others from that address. The address now keeps its count
  until its window ends; the count of each account is reset as before. Behind a shared address a public NAT counts everyone's
  mistakes together: raise the address limit or shorten its window in the password policy if yours needs it.
- **A stopped model no longer holds every call of a changed context.** Its verdict not coming in time now spares that context
  the wait for a minute: a general resource goes on at once, a sensitive one is refused at once.
- **A stolen session no longer gets its first answers before the decision.** A session cookie used from another address
  went on while the model was deciding, so the first two or three calls answered, on a resource declared sensitive too. A
  person's call to a `@Protectable` method whose session, address or browser differs from the user's last decision, the one
  in force or one of the last 24 hours, now answers after its verdict: an ALLOW runs the method, a CHALLENGE, an ESCALATE or
  a BLOCK stops it first. **Such a call waits for the model**, up to `contexa.security.zerotrust.agent.flight.wait` (40
  seconds): after a change of network, on a user's second device each time the user changes device, and on the first call of
  a new sign-in while the last decision still names the session before it. A user's calls at once ask the model once and
  wait for its verdict, up to `contexa.security.zerotrust.agent.flight.queue-capacity` (20) on each server; past that a call
  gets a 429 with `Retry-After`. Past the wait, or with a model or a store that fails, a general resource goes on and a
  sensitive one is refused for that call alone: with a CHALLENGE, or with a 429 and `Retry-After` while a store is down.
  Calls of the same session, address and browser go on as before, with the decision after the response. A user with no
  decision on record is not compared, nothing is held in SHADOW, and service clients go on as before. A
  `ZeroTrustActionRepository` of your own compares nothing until it implements `decidedContext`.
- **A right taken away ends on the next request, for a token too.** A token's `roles` and `authorities` claims were added to
  what the account holds, so an administrator stripped of a group stayed one until the token expired, and a refresh kept
  it going for as long as the refresh token lasted. A token now carries what the account holds at each request and the
  token's scopes, and a refresh hands out a token naming the account as it is. A still valid access token is given back
  by a refresh as before, unless it names a right the account lost: that one is replaced. A refresh is refused with
  `invalid_grant` for an account that is gone, disabled or locked, at `/oauth2/token` as well, and the BLOCK, ESCALATE and
  CHALLENGE that stopped only the refresh entry point now stop `/oauth2/token` too. A disabled account's token ends at
  once; a locked one goes on until it expires, as a session does. **Check:** a role that lives only in the claims of your
  identity provider's token no longer counts for a user with an account here: give it to the account. A
  `OAuth2TokenCustomizer` of your own replaces Contexa's, so `/oauth2/token` then checks nothing at a refresh.
- **A new password ends what the old one opened.** A password changed on the password page, or by an administrator in the
  console, left the sessions and the tokens of the account running, so a thief stayed in after the owner changed it. Once
  the change has committed the sessions of the account end, the one that changed it too, and so do its tokens, those an
  agent's client got for the user by token exchange included: a disabled and a deleted account now end those as well. Both
  stores behave alike. A console session under `HOST_OWNED` ends on its next request and leaves the application's HTTP
  session alone. A store that is down does not fail the change: the password stands, what could not be ended keeps running
  and the log says so at ERROR. A password an administrator sets now dates the account (`password_changed_at`), which starts
  its age under the password policy anew.
- **A stolen password no longer changes the password.** `POST /contexa/password-change` asked for the current password and
  nothing else, of anybody: whoever held a stolen password passed the second step by and locked the owner out. It now
  serves two people. An account whose password expired, which cannot sign in, changes its password with the current one,
  and the owner signed in changes their own: a session of another user, a session that waits for its MFA and an agent
  acting for the user are neither. Under `ENFORCE` a stored CHALLENGE, BLOCK or ESCALATE stops a session, and a BLOCK or an
  ESCALATE stops an expired account; a disabled account changes nothing. Whatever refuses answers exactly as a wrong
  password does, and the right password refused is not counted as a failed sign-in, which would let whoever holds it lock
  the owner out.
- **A one-time code of the HOST_OWNED step-up now takes a limited number of answers.** The right code passed after any
  number of wrong ones. A session context now gets `contexa.auth.mfa.max-retry-attempts` answers (5, as Contexa's own MFA).
  The last one spent, the codes mailed for that context are discarded, and it answers nothing more, right or wrong, until
  a new code is mailed for it. The answers are counted for the session context, an address and browser included, and at
  once across nodes with the Redis store, so requests at once pass no limit. A stolen cookie is another context: its wrong
  answers use up its own and leave the owner's answers and any code the owner asked for. The response to an answer past
  the limit is the response to a wrong code, and the screen tells either to check the code or ask for a new one. The wait
  between two mails is lifted for the new code, once in the five minutes a code lives, so wrong answers do not fill the
  mailbox.
- **A user's name can no longer reach the decisions of a console session or an agent.** A console session keeps its
  decisions under `console::<user>` and an agent acting for a person under `<user>::agent::<agent id>`, and a user is kept
  under the name. A user named `console::admin` therefore shared the console administrator's key: a BLOCK of that user
  threw the administrator out of the console, and a delegated agent's decisions could reach a user named as its key in
  the same way. A name that reads as such a key, in any spelling, now has a key of its own (`ctxa-user::` and the name
  spelled out), in the decisions, the block flags and signals, the block records and the learning. So does a name that
  contains `agent::` or starts with `ctxa-user::`. Every other name keeps its key, so what is stored under it stays. What
  was stored for a user named so before this version cannot be told from what the console or the agent stored: it stays
  under that key and the user starts again. Deleting a user also no longer removes the learning of an agent whose id is
  the user's name.
- **A sign-in flow no longer mails a code in another user's name.** The name of a code request comes from the form, and it
  was compared with the flow only after the mail had gone: a user could send anyone a code from their own sign-in. A flow
  now asks for the code of its own user, and any other name is refused before a code is made.
- **An old BLOCK no longer turns into a second step at the sign-in.** A decision past
  `contexa.security.zerotrust.analysis.max-age-ms` was read as a CHALLENGE, a BLOCK and an ESCALATE too, so an hour after
  a BLOCK the password step asked for a code instead of refusing. A restriction now answers the sign-in however old it is.
- **A password alone no longer fills the user's mailbox.** Every request for a code mailed one, so twenty requests sent
  twenty mails. Contexa's own sign-in now mails an address once in `contexa.auth.mfa.email-resend-interval-seconds` (120
  seconds, a setting without effect until now), requests at once included, on every node with the Redis store. A request
  inside the interval is answered as any other and stays at the code: the code mailed before stays good, and nothing tells
  whether an account exists. A mail that failed starts no wait and a used code ends it. Zero or less keeps 120 seconds and
  logs an error at start. While the Redis store is down no code is mailed. A `OneTimeTokenGenerationSuccessHandler` of your
  own gets a token with an empty value for such a request.
- **A stored ALLOW no longer waives the second step of a new sign-in.** The decision was reached for another request and
  the sign-in read it by user alone, so a stolen password met no second step from any address or browser while the
  victim's ALLOW lasted. Under `CONTEXA_OWNED` a person's sign-in through an MFA flow now always meets the second step,
  after a sign-in moments before too. The ALLOW still answers the requests of its own context, a stored BLOCK, ESCALATE
  and CHALLENGE answer the password step as they did, and an approved agent's account keeps its own policy. A policy of
  your own can still waive MFA: see the evaluators and the provider you can replace.
- **The code the victim passes no longer frees the attacker's session.** A CHALLENGE is answered per session: the
  session that passed the code goes on, and every other session of the user stays stopped until it answers for itself
  or the CHALLENGE would have lapsed. A user on several devices verifies on each. An administrator's override ends it.
- **A stolen password no longer registers a passkey.** A passkey answers a CHALLENGE, so registering one now needs a
  confirmed user. Under `HOST_OWNED`: a code mailed to the user's own address, or the application's own MFA sign-in in
  the last five minutes. Under `CONTEXA_OWNED`: a session that completed MFA; any other verifies first and comes back.
  A CHALLENGE is answered first, and a BLOCK or an ESCALATE refuses it.
- **Logging out ends the sign-in it left waiting for a code.** With the Redis store the `MFA_SID` cookie and the code could
  finish it from another browser. A session that ends, by logout or otherwise, now ends the MFA flow it started, in both
  stores.
- **Every spelling of a name meets the decision of that name.** A BLOCK of `plain-k9` also stops `PLAIN-K9` and a
  full-width spelling. If names of your application differ by case alone, set
  `contexa.security.zerotrust.normalize-user-keys=false`: with it on, a restriction of one reaches the other. A BLOCK
  stored by an earlier version stays in force; other decisions under a name with capitals start again after the upgrade.

### Fixed

- **A CHALLENGE no model decided stays short through a Redis outage.** What a server read last stands while Redis does not
  answer, and it stood for a CHALLENGE's half hour even when the CHALLENGE came from a failed analysis and lasts a minute. It
  now stands for that minute, and a CHALLENGE held for other sessions stands as long as what Redis holds of it.
- **A forced logout outlives a Redis outage.** A logout asked for while Redis was away, for a disabled or deleted account or
  by a risk signal, ended in an ERROR line and nothing else. It now waits in the memory of the node that was asked and is
  applied once Redis is back, the sessions and what a logout removes with them; the version that makes open sessions read
  their accounts moves on too. The audit log shows that it waited and that it was applied. Until then the sessions go on, and
  a restart of that node during the outage loses it: an ERROR says so at the stop, and the audit record stays. A risk signal
  a store did not let Contexa act on is answered with an error and is acted on when it is sent again.
- **A sensitive resource does not go on without its method policies.** While the database does not answer, a call whose
  policies could not be read went on, and a DENY among them was missed. A call to a resource declared sensitive is now
  refused for that request with a CHALLENGE, whatever the model answered: a decision does not speak for a policy. A general
  resource goes on as before, and in SHADOW nothing is refused.
- **A double click on the right code no longer ends the sign-in.** A second request that reached a flow being verified
  ended the flow: both clicks failed and the user started again with a new code. The second request is now answered
  `429 MFA_BUSY_RETRY` and changes nothing, so wrong codes sent at once are read one at a time and the limit on the codes
  read stands. A verification that has not moved for `contexa.auth.mfa.state-machine-timeout-ms` (10 seconds, a setting
  without effect until now) ends the flow as before.
- **The in-memory stores have a limit in bytes.** The session histories, the work profile and role scope observations and
  the personal and organization baselines of standalone mode were bounded by count only: by calculation 8 GB of session
  history at worst, and about a hundred users' work profiles past a usual heap. Each now keeps within a twentieth of the
  heap, between 16 MiB and 512 MiB; past it the session, user, scope or baseline written the longest ago goes whole, and a
  WARN says so at most once a minute. What a decision reads changes only past the limit, by the oldest input. Redis keeps
  to its own memory limit.
- **The line of analyses has a limit.** Events coming in faster than they were analysed queued without end. A twentieth of
  the heap, at most the monitoring queue's size, now bounds what is accepted and not finished. An event past it is not
  analysed: it stays a fact of its session, it is counted, and an ERROR says so at most once a minute. Nothing upstream
  waits for room, and a full line counts as the analysis being behind.
- **A synchronous call no longer waits 40 seconds for a store that is down.** The analysis of a synchronous call runs off
  the request's thread, on the application's own Redis client. While a store is down the request now waits three more
  seconds at most: a verdict in that time still answers, a restriction in force stands, and otherwise the call is the
  outage it is, which lets a person through and answers an agent that the analysis is busy.
- **An application on Spring Boot's own user keeps it with only the starter added.** The OAuth2 libraries the starter brings
  made Boot give that user up, so its generated password was gone and nobody could sign in. An application that configures
  OAuth2 or SAML in its settings still gets no such user, as without Contexa; one that signs in through OAuth2 with beans of
  its own and no such settings keeps a user nobody knows the password of.
- **A Contexa database the account may not fully use no longer stops the application.** An account that may not create the
  `vector`, `hstore` or `uuid-ossp` extension stopped a `HOST_OWNED` start with a stack trace. The application now starts
  without Contexa, as it does when the database is down, with one ERROR that names the statement an administrator runs. The
  ERROR for a database that is down now reads "cannot be used".
- **`DISABLED` and `OBSERVE` send nothing to the analysis.** Sign-ins and other events still reached the model, at the
  model's cost, although a protected method did not. Nothing is analysed or kept for the session in these modes now.
- **The first requests after a start are decided.** The agent started after the web server had opened, and an event of that
  moment was dropped, so the first user passed without a decision. It now starts before the server opens.
- **A sign-in's decision is found by its request.** Its observation, audit and sealed rows had no `request_id` or
  `correlation_id`; they now carry the event id, as a protected call's rows do.
- **The console's policy list reads a page.** Each opening read every policy into memory and cut the page there
  (`HHH90003004`).
- **A user of Contexa no longer gets a second row.** Where Contexa owns the sign-in the bridge made a copy `brg_<hash>` of
  each signed-in account, and what read the subject of a request read that copy, without the account's groups and roles. It
  now reads the account. Rows an earlier version made stay in `ctxa_users`. The console's user list shows a copy of an
  application's user under the application's name for it.
- The start names an `actions` value of `@Protectable` outside the action families; the value had no effect on the request.
- An MFA code submitted after its session ended counts against no account, and writes no ERROR. It was sent to the lock's
  count from the failure handler, which failed there for want of a transaction; the account's failures are counted by the
  failure event of the sign-in, as before.
- Lifting a block record that is lifted already, or deleting one still in force, is answered with 409 by the block list's
  API, and an id with no record with 404, instead of 500 with an ERROR stack. The console's pages say why without an ERROR.
- **A CHALLENGE decided in the request takes the browser SDK to the step-up.** The request filters named it in `error` and a
  synchronous decision in `code`, so the SDK, which follows `error`, stayed on the page. Both answers now carry `error` and
  `code`: `error` is `MFA_CHALLENGE_REQUIRED` where a step-up can go on and `ZERO_TRUST_CHALLENGE` where none is offered, `code`
  is `ZERO_TRUST_CHALLENGE`. A synchronous answer also carries `challengeNoticeUrl`, and every other synchronous refusal
  carries its code in `error` too.
- The guidance for running without decisions names `contexa.security.zerotrust.mode=DISABLED`. The
  `contexa.autonomous.enabled=false` it named stopped the start of an application with `@EnableAISecurity`, on a bean of
  Contexa's. That setting takes away the decision engine all of Contexa reads, so an application that keeps its sign-in now
  writes one ERROR and starts without Contexa, as with Contexa's database down; where Contexa owns the sign-in the start is
  refused and says why. To turn off only the decisions, use `contexa.security.zerotrust.mode=DISABLED`.
- A new session of a user no longer writes `Context binding hash mismatch` at ERROR: it is the ordinary way to a new decision.
- Contexa adds no `BeanPostProcessorChecker` line to an application's start log.
- **A store outage is no longer an outage of the application.** Redis or Contexa's database that stops, freezes or runs out
  of connections used to hold every request of a signed-in user, the pages no decision protects included: a minute for each
  read on Redis, and a minute on the pool. A request now waits about a second once and then not at all, and everything
  comes back by itself. The application's own Redis client and pool settings are not touched, and the engine's threads keep
  their waits. While a store is away a protected call goes on as the operating mode specifies, and the interval is written
  to the log and the audit log as calls without a decision.
- **A restriction outlives the outage.** A BLOCK, CHALLENGE or ESCALATE this server read stays in force while Redis does not
  answer, and a BLOCK this server never read is found in `ctxa_blocked_user`.
- **A technical failure is no denial.** An authorization check that did not finish is recorded as `UNKNOWN`, not `DENY`, so
  an outage no longer ends in a permanent BLOCK of normal users.
- **Authenticated Kafka works.** Contexa's clients take `spring.kafka.security.*`, `ssl.*`, `properties.*` and SSL bundles as
  Spring Boot does; what Contexa's delivery depends on stays Contexa's.
- A start that Redisson's JCache provider stopped says why and names `spring.cache.type=caffeine`.
- The start names Redis Cluster at ERROR, which this release does not support, and, in standalone, that a restart ends a
  BLOCK and a CHALLENGE in force.
- **No request reads as undecided while an ended ESCALATE is being replaced.** Concurrent readers of an ESCALATE past its
  time could answer PENDING_ANALYSIS: one found no analysis, another wrote the replacement, and the first then met the
  new last-verified record. The replacement now answers them too, in both repositories.
- **`@EnableAISecurity` can stand on any configuration class.** Declared on the class that also declares the application's
  `PlatformConfig`, or on one parsed before it, the application stopped at start with two `PlatformConfig` beans. The
  application's configuration classes are now parsed first, so every conditional bean of Contexa's configuration gives way
  to the application's wherever that is declared. Contexa's values reach the `Environment` after those classes are parsed
  and before the auto-configurations.
- **A decision at a protected method is answered by Contexa whatever exception handlers the application has.** A catch-all
  `@ExceptionHandler(Exception.class)` at the top order turned a CHALLENGE into its own answer and ended a BLOCK with a
  broken connection. `ZeroTrustEnforcementExceptionResolver` now answers Contexa's own exceptions ahead of every advice, of
  a handler inside a controller and of an application's resolver. The answer is always JSON, in Contexa's field names; every
  other exception stays the application's.
- **A `@Protectable` method runs in `@Scheduled` and `@Async` work.** A call on a thread that holds neither a user nor a
  request failed with `AuthenticationCredentialsNotFoundException`. There is no one to decide for, so it now runs: the first
  run of each method writes a warning, and `ctxa_ai_security_llm_trigger_suppression` keeps a `RAN_WITHOUT_USER` row a minute
  per method with the calls counted. A user carried into the thread is decided, and a request with no user stays refused.
- **A live session id no longer leaves the running application.** The sealed evidence, the audit log, the decision
  observations, the vector store and the model's input name a session by a reference (`sid-` and 24 hex digits of its
  SHA-256): two records of one session carry the same reference, and the reference signs nobody in. The session stores
  and the event a node hands to another keep the id, since they are keyed by it. Rows already stored stay as they are.
  The `session_id` of the audit log and the observations is now that reference, so it cannot be matched to a live
  session: `ctxa_active_sessions` and the session store still hold the id.
- A query string keeps the names of its parameters, not their values (`pin&newPwd`): in the sealed evidence, the decision
  observations and the session's records. A part without `=` is left out, since it may be the value itself. The model's
  input never held a query.
- The arguments of a protected method hide the value of a pin, a passcode, an OTP, a card's security code or a social
  security number as they hide a password or a token, by the argument's name. The name stays, and the other arguments
  stay as they were: the v21 prompt reads them, and the seal keeps what the model read. The value of a secret passed
  under an unrelated name cannot be told by its name, and a class compiled without `-parameters` has no names to read.
- The analysis key kept with a decision names the session by its reference.
- **A sealed package changed without the signing key no longer passes the re-inspection.** Where the installation signs,
  a package without the signature it should carry fails instead of reading as not verifiable, whatever schema it names:
  a decision changed, its schema lowered and its hash computed again used to pass in full. Packages captured before the
  oldest signed package kept are the ones sealed before a key existed and stay as they were. Run a re-inspection after
  this version to read the packages already kept: the inspector version moves to 28.
- The re-inspection follows `previous_package_hash`: the package after one that was removed fails, naming the hash that
  is gone. A package the retention may have taken (older than the shorter of `retention.period` and
  `retention.clean-period`) is no finding. The limits of the seal are in `SECURITY.md`.
- The console's version comparison and shadow pairs read the sealed decision, which the package hash covers, not the
  `decision_jsonb` copy beside it. Its package list and resource counts read the sealed request facts the same way, not the
  `request_facts_jsonb` copy.
- **A key nobody held no longer leaves a sealed package unread.** With keys configured in
  `contexa.security.evidence.signing`, a package from the time the active key signs that names a key the installation does
  not hold fails instead of reading as not verifiable. Packages from before that time keep reading as not verifiable, as
  every package does under an ephemeral key. A package lowered to an older schema with any text as its signature no longer
  passes either. Run a re-inspection to read the packages already kept: the inspector version moves to 29.
- **A decision record follows the same rule.** Once older sealed records are kept, a record without its hash or signature
  shows as changed on the security monitor instead of as not verifiable, and so does one that names a key never held once
  older records are signed with the active key. A custom `EvidenceSigner` answers `keepsItsKeys()` to take part in this.
- What a person is asked to confirm for an agent keeps the request's path and query, but a value that opens something is
  masked: by the name of its parameter (`token`, `pin`, `password`, ...), by its own shape (a signed token, a provider's key,
  a national id), or inside a nested URL. The confirmation stays bound to the very request.
- A session id no longer reaches an approval request or the audit line of a model call: both name it by its reference.
- **A layer model set in `contexa.security.tiered.llm.layer1.model` or `layer2.model` runs with Anthropic from the
  settings alone.** The second layer used to run on the first layer's model without a word, and one chat model bean of
  the second layer's model pulled the first layer onto it too. Each layer's model is now made from the Anthropic chat
  model, with the same client and default options of its own, so a model that refuses sampling values is not sent the
  defaults of another one. No chat model bean of your own is needed.
- A layer model that cannot be made (no `contexa.llm.bindings.chat` binding and a provider other than OpenAI or
  Anthropic, or another provider's model id on Anthropic) is told at the start in one ERROR line: the layer, the model
  set and the model that runs in its place. The application starts as it did. A wrong model id of the same provider
  cannot be told without a paid call and fails at the first call of that layer.
- A decision record names the model that answered, else the model that was asked. A decision that never reached a
  model (`QUEUE_TIMEOUT`, `REJECTED_BACKPRESSURE`) names none; it used to name the configured model.
- **Contexa no longer fills the application's heap under load.** Every request kept a snapshot of its session
  for 30 minutes after its decision, each with up to a hundred decoded decisions, so 10,000 requests took hundreds of
  megabytes and a 384 MB application stopped with `OutOfMemoryError` after about 1,500 decisions, in both infrastructure
  modes. What the requests hold now has a limit in bytes, a twentieth of the maximum heap between 16 MiB and 256 MiB: past
  it the committed requests give up their snapshots first, the longest committed first, and their committed mark stays,
  so nothing is recorded twice. A request no analysis reaches keeps only that mark. Nothing a decision reads changes: the
  session's history and the prompt are as they were. A later resolution of a request whose snapshot went reads the
  session again.
- The other per-decision places on the heap have a limit in bytes as well: the canonical contexts kept while a prompt is
  built (a thirty-second of the heap) and the documents of the cached vector searches (a thirty-second of the heap,
  beside `contexa.security.tiered.vector-cache.max-size`, which still holds); a search or a context not kept is resolved
  again to the same result. The prompt snapshots waiting for their sealing are held within a twentieth of the heap, the
  oldest going first. The event collectors keep the id and time of the recent events, not the events with their whole
  context. An AI operation that fails or streams to its end no longer leaves its audit entry in memory.
- **What an administrator changes reaches the sessions that are open.** Disabling a user ends the user's sessions at once,
  and a change of groups, roles, permissions or the role hierarchy is read again by each open session on its next request.
- **The console's administrator is not the application's user of that name** under `HOST_OWNED`: a BLOCK of one no longer
  locks the console of the other, in either direction, and the block list stays open to a console session.
- **A session under a BLOCK no longer lifts it itself.** The block list stays open to a blocked console session, but its own
  record and its own CHALLENGE take another administrator, or a verification passed in that session: the list then offers
  a one-time code to the account's address, or its passkey, at `/contexa/admin/blacklist/step-up`. No spelling of the name
  gets around this. An administrator's own record can no longer be deleted that way either, and the attempt is audited:
  `BlockedUserService.deleteBlockRecord` takes the acting administrator now. **A sole administrator needs mail configured
  and a real address on the account, or a second administrator**: without a factor nothing lifts the console's own BLOCK
  from the console. Under `CONTEXA_OWNED` the same rule reads the shared account, and its own record takes another
  administrator or a verification passed in that session.
- **The only administrator under a BLOCK has a way out** under `CONTEXA_OWNED`, where the console and the application share
  one account. After passing MFA on the screen of the BLOCK, an administrator reaches the people of the block list in that
  session, and no other page of the console or the application, the agents' tab included. A verification is kept for the
  session that passed it and ends with the BLOCK it answered.
- A BLOCK decided over a CHALLENGE that other sessions still held could be lifted through the CHALLENGE release. It stays.
- **A save of the console's system settings no longer fixes the zero trust mode.** While no mode is stored,
  `contexa.security.zerotrust.mode` applies and the form shows it; saving any other setting used to store that mode, and
  the setting of the next deployment then silently no longer applied. A form that names no mode, or the mode in effect, now
  leaves it unset, and another mode is stored as before. A row an earlier save filled keeps its value: set
  `security_zerotrust_mode` of `ctxa_system_settings` to NULL to hand the mode back to the setting.
- **Behind a proxy nobody named, one person's typing no longer stops everyone, and a forged header escapes nothing.** A
  sign-in is counted against the address it connected from, whatever `X-Forwarded-For` says, and the header never switches
  the address limit off or lifts a block of it. When a request carries the header,
  `contexa.security.tiered.security.trusted-proxies` is empty and the connection comes from a private range, a link-local
  address or the machine itself, that address may be a proxy with everyone behind it, so its limit is ten times the
  policy's and an ERROR names the setting. A connection from a public address, and any connection without the header, keeps
  the plain limit on the same count, so sending the header now and then gains nothing. The lock of each account works as
  before. **Set the setting if you run behind a proxy**: until you do, all users behind it share one count and one block,
  and anyone on that network who adds the header gets the ten times too.
- **A model outage no longer locks users out for half an hour.** A CHALLENGE no model decided (the analysis failed: an
  HTTP error, an empty or unreadable answer, a time-out) is marked, lasts 60 seconds instead of 30 minutes and gives way
  to what the model decides next. While it lasts the model is asked again about the same request, every 10 seconds, at
  most three times, so a model that is back frees the user without any step of theirs. A CHALLENGE or a BLOCK the model
  decided stands as it did: the mark never shortens or replaces one, in Redis or in memory.
- **The decisions after a passed step-up are told of it.** Under HOST_OWNED the application's sign-in stays as it was,
  so every later decision read `MfaVerified: false`, however recent the code. A passed step-up is now kept for an hour as
  a fact of the context it was passed in (the session, its address and its client): the requests of that context carry
  `mfaVerified`, `challengeVerifiedAt` and `lastMfaUsedAt`, under both ownerships. Another session of the user still reads
  it as `RecentMfaElsewhere`. The facts changed, not the wording of a prompt; what the model decides with them stands.
- **An event Kafka does not take is analysed where it was made.** Where a topic cannot be used (a broker that does not
  create topics, a broker that is down) a sign-in and an asynchronous `@Protectable` reached no decision. An event whose
  send fails, or that waited past a send's limit, now goes to the analysis of the node that had it, as in standalone,
  and to the dead letters as before. Every event keeps one id, so one that reached the broker after all, or that is
  replayed from the dead letters, is the same event and is not analysed twice. The publisher's queue still drops, counts
  and reports what it has no room for: nothing may hold the request's thread.
- **Filling the analysis no longer keeps a decision away.** With a slow model and many users a user the model would stop
  got no decision for as long as the load lasted. A session without a decision of the model now goes first at every
  line of the analysis (the session's turn, the analysis threads, a model server's gate), one user holds at most eight
  analyses however many sessions it opens, and a person's queued call that a decision in force answers is not analysed
  again: calls that waited behind a decision cost that decision and not one each. A sign-in is always analysed.
- **While the analysis is behind, a sensitive resource does not go without a decision.** Behind means as many analyses
  in progress as `security.plane.llm-executor.backpressure-queue-threshold` (96). A call to a resource declared
  `importance = SENSITIVE`, or whose sensitivity is `HIGH`, `CONFIDENTIAL`, `RESTRICTED` or the like, with no decision in
  force asks for its analysis, waits three seconds for the verdict and is then refused with a CHALLENGE that is not
  stored. Any other resource passes as it did, and nothing changes while the analysis keeps up.
- **A synchronous `@Protectable` no longer holds the application's thread as long as the model is given.** A request
  waits for its verdict at most `contexa.security.zerotrust.agent.flight.wait` (40 seconds), a person's as an agent's.
  Past it the request is refused with a CHALLENGE that is not stored, the analysis goes on and stores its decision for
  the next request. An application on a slower model raises that setting.
- **A user can answer a CHALLENGE in `contexa.infrastructure.mode=distributed` whatever the sign-in is made of.** An MFA
  flow stored in Redis could not be read back when the sign-in held a read-only collection (a one-time token or a
  remember-me sign-in with Contexa's user or Spring's `User`, a JWT, an OAuth2 login) or an object the reading node
  cannot load, and the user could not go on. A stored flow now keeps of a sign-in of any kind only what the flow reads:
  the name, the authorities, whether it is authenticated and the facts of the login. The principal, the credentials and
  the application's classes no longer reach Redis, and a stored flow keeps the login's method and time as the in-memory
  flow does. An attribute that cannot be stored or read back (a value of the application's policy) is left out with an
  error in the log, and the rest of the flow stays.
- A stored flow that cannot be read now stops the request and stays as it is. It used to be replaced by the copy the
  request held, without the version check.
- A request running beside a write no longer finds no flow in Redis and ends it.
- Flows in progress in Redis when this version starts cannot be read and start again: the stored form changed.

### Added

- **An administrator unlocks an account.** A locked user's page in the console has an Unlock button, and
  `POST /contexa/admin/users/{id}/unlock` ends the lock and the count of failures ahead of time. The audit records who did
  it. A limit on the address the failures came from stays.
- **A way out for a user with neither a mail address nor a passkey.** An application tells a user's address with a
  `BridgeUserEmailProvider` bean. An administrator can enter the address on the user's page, or release a CHALLENGE on the
  block list; the release is recorded in the audit and nothing is learned from it. The user who passes a code is offered
  a passkey at once, and `/contexa/step-up` is the page to link from your account menu. The start log and the console's user
  list say how many users could not answer a CHALLENGE.

### Changed

- **An ALLOW now lasts 15 minutes instead of 15 seconds.** The 15 seconds were a value for fast tests. Set
  `contexa.security.zerotrust.allow-validity` to change it; production belongs between 10 and 20 minutes, and a time
  outside that range is kept and said once at the start. A time that is not positive reads as the default, because a
  repository would keep the ALLOW for ever. While an ALLOW lasts, the asynchronous requests of the same session,
  address and browser are not analysed and not learned; a change of any of the three, and every synchronous
  `@Protectable` call, is analysed as before. Tests that wait for a next decision set the time lower.

- **Every database object Contexa creates starts with `ctxa_`**: tables, views, sequences, indexes and named
  constraints (`users` is now `ctxa_users`, `contexa_schema_provenance` is `ctxa_schema_provenance`). A table of your
  application with a plain name (`users`, `role`, `audit_log`, ...) is never read, changed or renamed, even in the same
  database. The tables Spring Security and Spring Authorization Server fix in their own SQL (`one_time_tokens`,
  `user_credentials`, `user_entities`, `oauth2_*`) are used under the prefix too, ShedLock's table is `ctxa_shedlock`,
  and the vector store's default table is `ctxa_vector_store` (its index `ctxa_vector_store_index`, the name Spring AI
  looks for).
- **An existing Contexa database is moved automatically**, in one transaction, when the data source is created, before
  any bean reads from it: tables, sequences, indexes, constraints and the recorded ownership of the tables follow, and
  data and sequence positions stay as they were. Only a database that has all of Contexa's marker tables under the old
  names is moved; if only some of them exist, they are taken for the application's own and left as they are, and if
  both names exist for a table the start stops without changing anything. Nodes that start together are safe (one
  moves the database under a database lock, the others wait and find it moved), but a node of the earlier version
  cannot run against a moved database: stop every node of the earlier version before the first node of this version
  starts, and keep a backup as for any upgrade.
- `spring.ai.vectorstore.pgvector.table-name` and `contexa.rag.etl.vector-table-name` default to `ctxa_vector_store`; a
  configuration that names `vector_store` explicitly points at a table Contexa no longer creates.
- **A failed Layer 2 call no longer ends in a BLOCK.** With `contexa.security.tiered.layer2.allow-escalate-final-action`
  off (the default) a model error or a time-out at Layer 2 ends as `layer2.escalate-fallback-action` (CHALLENGE by
  default, answered with 401) instead of 423 and, five minutes later, a BLOCK of a user no model judged. A CHALLENGE or
  BLOCK the model already decided stands when a step after it fails. An ESCALATE an earlier version left in the store
  ends as the same action when it is read, so nothing is promoted any more; a BLOCK promoted before the upgrade stays
  until it is released. With the setting on, the 423, the analysis-pending screen and the promotion stay as they were.
- **The address limit of the login policy now stops a password sign-in**, including the right password, until its block
  runs out. Its address follows the rule of every other decision: a forwarded header counts only from a proxy listed in
  `contexa.security.tiered.security.trusted-proxies` (or from `server.forward-headers-strategy`). **Behind a proxy that
  is not listed, all users arrive from its address and share one limit, so list it before you upgrade**; the log names
  the setting when such an address is blocked. Behind a listed proxy `X-Forwarded-For` is read from its end, past the
  listed proxies: list every proxy of the chain, a CDN included. `ClientIpResolver` in
  `io.contexa.contexacommon.security`, which believed any header, is gone; use `SessionFingerprintUtil.extractClientIp`.
- **A decision steps aside only for Contexa's own paths.** `/logout-report`, `/logout/report` and any path that only
  starts like one of Contexa's are the application's and meet the decision, and so do `/mfa/*`, `/api/mfa/*`, `/webauthn/*`
  and `/.well-known/*` beyond the paths the running flows and Contexa's discovery documents name. A path with a dot
  segment, an encoded character, a path parameter or a backslash never counts as Contexa's.
- The console's resource scan covers the application's own packages beside the configured ones.
- **A request decided in place no longer passes under a stricter decision stored meanwhile.** When a CHALLENGE, an
  ESCALATE or a BLOCK is stored for the user while another of the user's calls is being decided, that call is answered
  with the stored decision, whichever session it came from, in memory and on Redis alike. The audit record of the call
  keeps the decision of its analysis, marked as kept out where the agent decision record shows it. A CHALLENGE an agent's
  accountable person confirmed, a shadow boundary and an ALLOW of another session change nothing.
- **A user's password hash no longer reaches the caches.** The copies of a user the access decisions keep in the memory
  cache and in Redis (`contexa:cache:user_details:<id>`, `contexa:cache:user_details_name:<name>`) hold no `password`
  field, and `Users` leaves it out of JSON everywhere. Copies an earlier version wrote are read without it and taken out
  of the store at every start; while old nodes run they can write such copies again, and the last node to start takes
  those out. `AuthorizationContext.subjectEntity().getPassword()` is empty on a cached copy; nothing in Contexa reads it.

### Added

- `LibraryTableNames` (contexa-common) wraps the `JdbcOperations` handed to the Spring libraries' JDBC classes so that
  they use the prefixed tables; a test reads the libraries' SQL constants and fails when one of them names a table the
  wrapper does not know.
- HOST_OWNED and CONTEXA_OWNED: Contexa's enforcement is the same in both; they differ only in who owns sign-in, session
  and authorization (see the installation guide). HOST_OWNED enforces after the application's own chain, takes no part
  in its sign-in, session, cookie, locale or message bundle, asks for a mail code or a passkey on its own screens, and
  keeps a separate console chain with its own sign-in policy.

### Security

- **A BLOCK cuts a response that started under an ALLOW too.** Only a response started while the analysis was pending
  could be cut, so a stream begun in the 15 seconds an ALLOW lasts ran to its end past the BLOCK. Every response of a
  signed-in user under ENFORCE can now be cut, and carries `X-Contexa-Monitored` and `X-Contexa-Blocked-Redirect` unless
  `contexa.security.zerotrust.monitoring-headers=false`. What cuts a response stays a BLOCK received after it started.
- **The screens of a decision only lead to paths of the application**: `returnUrl` of
  `/contexa/zero-trust/analysis-pending` went to the browser unchecked, and `mfaUrl` of
  `/contexa/zero-trust/challenge-required` let a backslash, a tab or an encoded slash through. Anything but a path of the
  application, however it is encoded, now falls back to the screen's own destination.
- **A sign-in no longer tells who has an account**: the single-factor flows answer every refused sign-in with
  `Invalid username or password.`, as the MFA flows do, instead of `User not found: <name>`, `Invalid password` or
  `Account is locked`. A refused sign-in also costs one password comparison whether the account exists or not, so the
  time of the answer tells nothing either.
- **An attempt during a lock no longer moves the lock's end**: trying a locked account, even with the right password,
  pushed `lock_expires_at` back, so that anyone could keep the account locked. The count of failures still starts over
  when the lock has run out.
### Fixed

- **OAuth2 tokens: the second sign-in of a user no longer fails.** Spring Authorization Server reads the type of its
  columns from the database under the standard table name; under the `ctxa_` name it found none and wrote bytes into the
  text columns, which PostgreSQL keeps in hex form. It now reads the columns of `ctxa_oauth2_authorization`, and a
  table with `bytea` token columns keeps working. The script of the authorization server's tables now creates the same
  `text` columns as the schema. A stored row that cannot be read is removed at the user's next sign-in, which no longer
  fails on it: a person holding such a row signs in again.
- **OAuth2 tokens: the server accepts the tokens it issues.** Spring Boot's settings bean, which has no issuer, took the
  place of Contexa's, so `contexa.auth.oauth2.issuer-uri` reached the decoder and not the chain, and a token named the
  path of the login as its issuer. The chain now issues under the issuer of the settings or, when they name none, under
  `contexa.auth.oauth2.issuer-uri` (default `http://localhost:9000`), the rule the decoder already had. Set the key to
  the public address of the application.

## [0.1.1] - 2026-11-02

### Fixed

- The IAM seed scripts are read as UTF-8, like the schema. Java 17 takes its default charset from the operating
  system, so the Korean seed data was stored garbled on Korean Windows (MS949) and the startup failed on a unique
  constraint under a POSIX locale.

### Added

- `contexa.iam.seed.admin.password` (with `.username`, default `admin`, and `.email`, default `admin@localhost`)
  creates one administrator in the system administrators group at the start. An existing user with that name or
  e-mail is never changed, so a password changed in the admin console stays. Without the password nothing is created.

## [0.1.0] - 2026-04-13

### Added

- Open-source AI Native Post-Auth Runtime Control Plane baseline for Spring applications
- Runtime behavioral analysis and zero-trust control flow inside the application layer
- Request-time control actions including `ALLOW`, `CHALLENGE`, `BLOCK`, `ESCALATE`, and `PENDING_ANALYSIS`
- Identity, IAM, and AI runtime modules packaged as a coherent open-source core
- Spring Boot starter for simplified adoption
- Public security policy, contributing guide, code of conduct, issue templates, and CI workflow

### Clarified

- CONTEXA open-source core positioning as a downstream runtime control layer
- Relationship between the open-source core and separate enterprise operational surfaces
- Public links for documentation, benchmark entry, and security contact