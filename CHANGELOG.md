# Changelog

All notable changes to the open-source CONTEXA core are documented in this file.

The format is based on Keep a Changelog and the project follows semantic versioning in principle.

## [Unreleased]

### Security

- **A REST sign-in kept in the session gets a new session id, and the limit of sessions counts it.** A `rest(...)`
  flow with the session state signs in through Contexa's own filter, and that filter did not apply the session strategy
  of its chain as Spring Security's sign-in filters do. The session kept the id the browser came with, so a session
  someone had planted in that browser was signed in with the user's (session fixation), and
  `sessionManagement(session -> session.maximumSessions(n))` did not count the sign-in. The filter now applies the
  strategy before the sign-in is kept: a new session id, the limit of sessions, and a new CSRF token as after a form
  sign-in, so a page reads its token again after the sign-in. A sign-in the limit refuses
  (`maxSessionsPreventsLogin(true)`) is answered 401 and is not counted as a wrong password. A flow with the token
  state keeps no sign-in in the session and is unchanged. **Check:** on a `rest(...)` flow with `.session(...)`, the
  `JSESSIONID` after `POST /api/login` differs from the one before; with `maximumSessions(1)` the first browser reads
  "This session has been expired" after the same account signs in from a second.
- **An MFA sign-in that ends at the first step gets a new session id, and the limit of sessions counts it.** When no
  second factor is asked (the user's MFA is off, an agent account, a decision of the flow's policy provider), the first
  step completes the sign-in, and no filter of Spring Security handles it: with the session state it kept the session
  id the browser came with and was not counted by `maximumSessions`. A sign-in that goes on to a factor was not
  affected, since the filter of its last factor applies the strategy. The first step now applies the session strategy
  of its chain when it completes the sign-in, and a refusal of the limit is answered as a failed sign-in (401) and not
  counted as a wrong password. **Check:** with the session state and a user who needs no second factor, the
  `JSESSIONID` after `POST /mfa/login` differs from the one before.
- **A passkey sign-in kept in the session gets a new session id, and the limit of sessions counts it.** Spring
  Security's passkey configurer builds its sign-in filter without the session strategy its other sign-in filters get.
  A sign-in by passkey, alone or as the factor of an MFA flow, kept the session id the browser came with, and
  `maximumSessions` never counted it: the principal of a passkey sign-in is another object at every sign-in, so the
  registry of sessions could not tell that two sessions are one person's. A flow with the session state now gives the
  filter the strategy of its chain, and the strategy receives the sign-in under the person's entry of the user store,
  as the other sign-ins of the chain carry it. **Check:** with the session state, the `JSESSIONID` after a passkey
  sign-in differs from the one before; with `maximumSessions(1)` the first browser's session ends when the same
  account signs in by passkey from a second.
- **A form login of Spring Security no longer stands beside an MFA flow.** `http.formLogin(...)` written in the global
  customizer, or in a `rawHttp` of the flow, stayed in the chain of an MFA flow as a second password sign-in: a POST
  of the password to its address (`/login`, or the `loginPage` it names) signed the user in without the factors.
  A single form flow already put its own in its place. It is now taken out of an MFA chain before the chain is built,
  and the start logs a warning that says where its settings belong:
  `mfa(mfa -> mfa.primaryAuthentication(auth -> auth.formLogin(form -> form.loginPage(...))))`. Other sign-ins an
  application adds in the global customizer, such as `httpBasic()`, stay as the application wrote them and sign in
  as Spring Security defines them, in an MFA chain too. **Check:** with `http.formLogin(form -> form.loginPage("/signin"))`
  in `global(...)` and an MFA flow, `POST /signin` with a right password does not sign in, and the log of the start
  has one warning that names the flow.
- **A session signed in with a passkey alone stays the user's for what Contexa keeps by name.** On every request of a
  session Contexa may replace the authentication with one whose authorities follow the decision in force, and that
  replacement worked the user's name out from the principal alone. The principal of a sign-in by passkey alone is a
  user entity that is no `UserDetails`, so the name became that object's string
  (`ImmutablePublicKeyCredentialUserEntity@58f01ced`), different at every sign-in, and from the second request on the
  session was read under it: a decision reached for the user after the sign-in (BLOCK, CHALLENGE), the tracking of the
  user's sessions and a forced sign-out no longer met that session, and `Authentication.getName()` gave the
  application that string. The replacement now keeps the name of the authentication it stands in for. Form, MFA and
  OAuth2 sign-ins were not affected, and the token state already kept the name. **Check:** after a sign-in by passkey
  alone with the session state, a page of the application that prints `Authentication.getName()` prints the user's
  name on every request.

- **A limit of sessions per user is enforced for Contexa's accounts.** `sessionManagement(session ->
  session.maximumSessions(1))` set no limit: Spring Security counts the sessions of a user by its principal, each
  sign-in reads the account anew, and the principal of a Contexa account had no `equals` and `hashCode`, so every
  sign-in was a user of its own and no second session was ever found to end. Two principals of one account are now
  the same principal (as with Spring Security's `User`). The classes kept in a session keep their serial version, so a
  session stored by an earlier version is still read. **Check:** with a limit of one, the same account signs in from a
  second browser and the first browser's next request is answered "This session has been expired", in a form flow and
  in an MFA flow with the session state; before, both browsers stayed signed in.

- **A mail code signs in once, also when requests present it together, and a person's sign-ins that arrive together end
  each other as the limit says.** Two faults that showed only under concurrency, found by starting an application and
  signing one account in from many clients at once. The mail code was read and then deleted without asking whether the
  delete had removed anything, so every request that read it before the first delete passed: one code signed in 2 of 2,
  20 of 20 and 68 of 1000 clients of one account. The delete now decides, and the request whose delete removed the row is
  the only one that has the code. And a new sign-in read the person's earlier sign-ins, ended them and stored itself
  without anything holding the three steps together, so sign-ins of one person that completed together each found
  nothing to end and all stayed: with one sign-in allowed (`contexa.auth.allow-multiple-logins=false`, the default), 13 or
  14 of 20 stayed signed in. A new sign-in now takes a lock of the database on the person
  (`pg_advisory_xact_lock`) for the transaction that ends the earlier ones and stores it, so the next sign-in of that
  person waits and finds this one; sign-ins of different people do not wait for each other. **Check:** one account,
  20 clients past the password, the one code sent by all at once: one is signed in and 19 get 401; 20 sessions of one
  account each with a code of its own, sent at once: 20 complete and one stays signed in; 1000 different accounts at
  once all complete.

- **A call from a changed context waits for no verdict, and a sensitive resource is not let out to it before one.** A call
  from another session, address or browser than the one the user's decision was reached for goes on while it is analysed,
  as a protected call is meant to; the decision applies from the next request. What bounds the cost of this is the limit of
  new contexts: a person may ask for six decisions of a new context in a minute (`contexa.security.zerotrust.analysis.new-context-limit.decisions`, 0 sets no limit),
  and past them the call is refused with a CHALLENGE of its own and the model is not asked. A context takes one place for
  one question, which is that context against the decision on record when it was asked: the calls of one context at once
  take one place, and two contexts used turn about take a place at each switch, because a verdict that lands is another
  decision. A call for a resource declared `SENSITIVE` from a changed context that has no decision yet is the case that
  must not go on: a stolen session used from elsewhere is this call, and a verdict after the response comes after its
  data. It is turned away at once with "analysing, come back in a few seconds" (429 and `Retry-After: 5`, as for every request the engine had no time to analyse; a browser gets
  the analysis page), no thread waits for the model, and the analysis of that context is started once however many calls
  are turned away. The call after the verdict is answered by it: ALLOW lets it through, a BLOCK or a CHALLENGE stops it.
  A general resource, a sensitive resource from the context on record, and a user with nothing on record are not held.
  **Check:** a moved cookie asking for a sensitive resource gets 429 in well under a second with the model down or slow,
  and 200 after an ALLOW for its context; the same cookie asking for a general resource is let through at once; a person
  who switches between two browsers more than six times in a minute is challenged, and the model is asked no more.

- **An OAuth2 token generator of your own no longer takes Contexa's token checks away.** The authorization server asks a
  token customizer only from the generator it builds itself, so an application that declared an `OAuth2TokenGenerator`
  bean issued its tokens without any of Contexa's checks, and without a word at the start: a suspended agent got its
  token, the renewal of a person's token was not checked against the account, and a token exchange could outlive the
  token it exchanged. Contexa's checks now run in front of the application's generator, on the token about to be
  issued, so a refusal ends the issuance before the generator does anything. A JWT the generator signed with a key of the
  authorization server gets the claims the checks write where it has none of its own (`client_id`, `roles`, the login
  facts, the delegation), and an exchanged token ends no later than the token it exchanges; such a token is signed again,
  once, with the authorization server's encoder, only when its claims or lifetime had to change, and when that fails the
  token is not issued. Whether a token is the server's is told by its signature, checked as the resource server checks it,
  and not by whether its header names a key. A generator that signs with a key of its own, one the authorization server
  does not hold, gets its tokens back as it issued them, byte for byte: Contexa's resource server cannot verify such a
  token and does not accept it, and the claims Contexa writes and the limit on the lifetime of an exchanged token are not
  put on it; Contexa's refusals still come before the generator, and the log carries one warning, once in the process, at
  the first such token. The start also logs one INFO line naming the generator. Where Contexa's checks are not
  there to put in front (the application took the place of Contexa's token customizer with a bean named
  `contexaTokenCustomizer`), the generator is used as it is and the start logs a warning that nothing checks its tokens.
  **Check:** tokens of an application's own generator are now refused for a suspended agent (`unauthorized_client`) and
  while the agent registry cannot be read (`temporarily_unavailable`); its JWTs signed with a key of the authorization
  server carry `client_id` and the other claims Contexa writes; a token signed with a key of the generator's own, and a
  token that is no JWT (a reference token), are checked but get no claims added.
- **A token customizer of your own can no longer lengthen an exchanged token beyond the token it exchanges.** Contexa
  ends an exchanged token no later than the token it exchanges, but it did so before the application's customizers ran,
  so a customizer that set a later expiry took the limit away. The limit now holds after the application's customizers:
  they may shorten the token, or lengthen it up to the end of the token exchanged. Tokens of any other grant keep the
  lifetime the application gave them.
- **A failing agent registry no longer lets an agent's token exchange skip the delegation a person revoked.** The lookup
  of an agent by its client and the lookup of the tenant of its client ended as "no agent" and "no tenant" when the
  registry failed or did not answer in time, so an exchange read the client as no agent and skipped the check for a
  delegation the person had revoked, or looked the agent up in the wrong tenant, also when the suspension of the client
  had been read a moment before. Both lookups now end as "cannot be read": the token endpoint answers
  `temporarily_unavailable` (also in the report-only mode, which lets a revoked delegation through but not a registry
  that cannot be read), and the resource server answers 401 to a client's own token whose agent it cannot read, with one
  error line per client a minute and nothing of the cause in the answer. A person's sign-in and tokens issued to the
  internal client never ask the registry. **Check:** an `AgentClientDirectory` of your own throws
  `AgentClientStatusUnavailableException` from `activeAgentForClient`, `activeAgentForAccount` and `tenantOfClient`
  when it cannot answer, instead of returning an empty answer. The stamp the bridge reads from a request that already
  passed is unchanged: it leaves a client the registry cannot answer about unnamed and does not fail the request.
- **A token customizer of your own no longer takes Contexa's token checks away.** The authorization server takes exactly
  one `OAuth2TokenCustomizer<JwtEncodingContext>` bean and Contexa registered its own only when the application had no
  customizer (of any token type), so an application that declared one lost the refusal of a suspended agent's token,
  the account check at the renewal of a person's token and the rules of a token exchange (scope, lifetime, no exchange of
  an exchanged token), without a word. Contexa's checks now always run first, and the application's customizers (any
  number, in their `@Order`) run after them: what they add to the claims is kept, a refusal of Contexa's ends the issuance
  before they run, and one INFO line at the start says that they were composed. **Check:** the application's customizer
  beans keep their names but are no longer beans of that type (the server finds only Contexa's composed one), so code that
  injects one of them by that type gets the composed customizer; a bean you name `contexaTokenCustomizer` still replaces
  Contexa's whole, checks included, as before.
- **A failing agent registry no longer lifts the suspension of an agent.** When the registry could not be read (its store
  failed, did not answer in time, or all workers of the request path were held), the lookup of a suspension ended as "not
  suspended", so the tokens of a suspended agent were issued and accepted for as long as the outage lasted. The lookup now
  ends as "cannot be read", and the token endpoint answers a client's token request (its own, an exchange, a refresh) with
  `temporarily_unavailable` and the resource server answers a bearer token issued to that client with 401, without a word
  of the cause; the registry says why in one error line per client a minute, naming the client. A person's token issued to
  the internal client (Contexa's own sign-in) never asks the registry, so an outage does not touch it. **Check:** an
  `AgentClientDirectory` of your own throws `AgentClientStatusUnavailableException` from `suspendedAgentClient` when it
  cannot answer, instead of returning `false`; tokens of other registered clients are refused with the same answers until
  the registry answers again.
- **An MFA sign-in or request that fails inside no longer tells the client what failed.** When the processing after a
  successful MFA sign-in failed, the API answer carried the person's name, the failing step, the exception's class and
  message and the MFA session's identifier, and a request of the MFA flow that failed while it was processed carried
  the exception's type and message. Both now answer in general words that the sign-in or the request could not be
  completed; the details are in the log, and the log line of the failed sign-in now also names the MFA session and its
  state. The status codes and the `error` codes (`MFA_POST_SUCCESS_PIPELINE_FAILED`, `REQUEST_PROCESSING_ERROR`,
  `MFA_PROCESSING_ERROR`) are as they were. **Check:** a client that read `userId`, `causeType`, `causeMessage`,
  `mfaSessionId`, `mfaState` or `failedStage` from the answer of a failed MFA sign-in, or `errorType` or
  `errorMessage` from the answer of a failed MFA request, no longer gets them, and the `message` of a failed MFA
  sign-in no longer names the failing step; read the log instead.

- **The answers of the MFA flow to a state or a request it has no step for no longer name them.** A verified factor
  that left the flow in a state no step follows was answered with `Unexpected state: ` and the state's name, a flow
  found in a terminal state that has no answer with `Unknown terminal state: ` and the state, and a request of a kind the
  flow does not take with `Unsupported request type: ` and the kind's description. They now answer in general words;
  the state or the kind, the person and the MFA session are in the log. The status codes, the `error` codes
  (`MFA_PROCESSING_ERROR`, `UNKNOWN_STATE`, `UNSUPPORTED_REQUEST`) and the fields of the answers are as they were.
  **Check:** a client that matched on the text of the `message` of these answers must match on the `error` code.

- **The console's API no longer answers a fault of the server with the exception's text.** Resolving or deleting a
  block record, an agent learning action and the three generations of condition templates answered 500 with the
  exception's message (in the `error` field), which can name a connection, a statement or a class. They now answer that
  the action could not be completed and to see the server log, where the exception is kept as before. The status codes
  and the fields of the answers are as they were, and so are the answers to what the application refuses on purpose (a
  record that is not there or is in force, an administrator who may not do it, a form left incomplete). **Check:** a
  client that read the cause from the `error` of one of these 500 answers must read the server log instead.

- **The console no longer shows an administrator the text of a fault of the server.** When a save, a delete or a refresh
  failed inside, many pages and answers of the console carried the exception's own text, which can name a statement,
  a constraint or a class: a role that an account still holds was refused with the foreign key of the database, for
  example. This held for the users, groups, roles, permissions and role hierarchies, the policies and the policy center,
  the resources, the access center, the block list, the IP rules, the sessions, the agents, the password policy and the
  system settings. What the console refuses on purpose (a name taken, a record that is not there, a state that does not
  allow it, the last administrator, the policies a new one conflicts with, an agent that is not known) is told in its own
  words as before. Any other exception is told as "The action could not be completed. See the server log." and kept
  with its stack in the log. The status of each answer and the attribute or field that carries the text are as they
  were. **Check:** a script or a person that read the cause from one of these pages or answers reads the server log
  instead; where a page puts the text after a sentence of its own ("Failed to delete: ..."), the sentence stays and the
  general sentence follows it.

- **The policy center, the resource workbench and a value no enum has follow the same rule.** The answers of the
  creation of a policy from the center, of a quick policy, of a batch of policies, of the migration and the cleanup of
  policy expressions, of the rollback of a policy and of the batch definition of resources put the exception's own text
  in the answer; they now tell an action that could not be completed unless the services refused on purpose, and the
  exception is in the log. A filter or form value that is no constant of an enum (a status or an effect `BOGUS`) was
  answered with the JDK's "No enum constant" and the enum's class, on the console's pages and in the 400 of its API; it
  is now an invalid request parameter, with the 400 and the fields it had, or on the pages and answers named above an
  action that could not be completed, and the operators read the text in the log.

- **A session an older node tracked after the references were introduced is turned into its reference when the
  console reads the sessions.** The tracked sessions that a database kept under the value their cookie carries were
  moved to their references once, when the application started. In a rolling upgrade a node not yet upgraded goes on
  writing the cookie's value after that, so such a row stayed until the next start: it was listed under its
  reference, but ending it from the console did nothing, because the console looks the session up by the reference
  and the row was stored by the raw value. The list, the export and the ending of a session now first turn the rows of
  the raw value into references (a row forced out stays forced out, and two nodes doing it at once leave one row),
  and a move that fails stops none of them. The list and the export never showed the raw value and still do not. No
  setting is added. **Check:** a session served by a node that is not yet upgraded is ended on that node only once it
  is upgraded, since that node looks the session up by the raw value the console no longer keeps.
- **Requests of one agent that arrive together mail the person once.** The person accountable for an agent is mailed
  once while one of the agent's confirmations waits, and the agent's other requests are told on the console only; but
  the store was asked whether another confirmation waited and then saved the new one as two steps, so the first
  requests of an agent that arrived together each found the agent alone and each mailed the person (an agent could
  send as many mails as it could send requests at once). The store now saves the confirmation and answers whether
  another waited in one step, in memory and in the database alike (the database puts the saves of one agent's
  confirmations in an order with a lock of its own, taken inside the transaction of the save): of requests that arrive
  together exactly one is mailed and the others reach the console. A store written for the application keeps working
  with the old two steps unless it overrides `AgentConfirmationStore.saveNotingWaiting`. No setting is added.
- **Two administrators can no longer take each other's role at the same moment.** The console kept its last
  administrator by reading whether another one remained, so two administrators who each took the other's
  `ROLE_ADMIN` (in the user's page, in the access center, or by deleting each other) in the same moment each read the
  other as still there, both changes went through and the console was left with none. Every change of who administers
  the console now takes one lock first, the rows of the roles, held to the end of its transaction, and reads the
  administrators only after the change before it: the second change waits, then is refused with 409 like a change of
  the only administrator. No setting is added.
- **A role, a group or the role hierarchy can no longer be edited to take the console's last administrator.** Renaming
  or deleting the role that gives `ROLE_ADMIN` (or the role a hierarchy line places over it), taking that role from a
  group in the group's page or in the access center, deleting the group, and rewriting, deleting or switching off the
  hierarchy line all took `ROLE_ADMIN` from the last administrator without a word, as a change of the user already was
  refused. Each is now refused with 409 and the accounts that would lose the role named, on the page the edit came from
  (the access center answers `success: false` with the reason), and nothing of it is kept; a changed hierarchy is read
  as it would stand, before the console runs on it. An edit that leaves another administrator, and an edit of what the
  administrator does not hold, go through as before. **Check:** before renaming or removing the administrators' role,
  give `ROLE_ADMIN` to a second account.
- **Applications that share one Redis and one Kafka no longer read each other's state.** Redis keys carried no application, and every Contexa consumer joined the one consumer group `security-plane-consumer`. A BLOCK that one application put on a user was read by another application as its own (`403 ACCOUNT_BLOCKED` for a user it never blocked), and the consumers of the two applications shared the partitions of the security-event topics, so the events of one application were analysed by the other's consumer, model and database. An application with a `spring.application.name` now keeps everything Contexa writes to Redis (keys, the patterns it scans, locks, the channels of the block signal, the policy reload, the cache and the approvals, and the stored MFA flows) under `ctxa:<name>:` before the key it always had. Its consumer group is `security-plane-consumer.<name>`, every event it publishes carries the header `ctxa-app` with its name, and its consumer analyses only the events that carry its own name; the offset of an event of another application moves on at once, and the events skipped are counted (`other_application_events_skipped`). The servers of one application (the same name) share all of it as before. The name is lower case; a character other than `a-z`, `0-9`, `.`, `_` and `-` is written as `~` and the hex of its bytes, and a name longer than 48 characters is cut and ends in a digest. An application without a name keeps the keys and the group it had, and in the distributed mode it is told at the start, at INFO, to set `spring.application.name` when its Redis or Kafka is shared. **Check:** give each application that shares a Redis or a Kafka its own `spring.application.name`. An application that has one reads and writes new keys after the upgrade: its decisions, sessions, step-up codes and MFA flows start anew (the old keys expire or stay unread), and each learned baseline is copied from the old key to the new one the first time it is read (the old key is left, and removing a user's data removes both). A BLOCK and a learning quarantine have no expiry, so they are not left behind under the old keys, which another application sharing the Redis may have written: when an application that has a name starts, before the web server takes a request, it writes every block its own database holds in force (every recorded block that is not resolved) again as a BLOCK under its new keys, where there is none, and adds the scopes quarantined under the old key to its own, once (a scope an operator releases afterwards stays released). Nothing is copied from the old BLOCK keys. If the database or the Redis cannot be reached at that start, the application starts all the same, `Restrictions could not be restored` is logged at ERROR, and the write is tried again for about four minutes and then reported once more: until it succeeds a user whose block is only in the database is not stopped, so look for that line in the log of the first start. The BLOCK of an agent has no record in the database to write it from and is not written again. The consumer group changes its name, so the new group starts at the beginning of the topics, and events published before the upgrade carry no name and are skipped by an application that has one. Servers of one application that run different versions during the upgrade do not see each other's state.
- **A restart no longer lifts a BLOCK that the database holds in force.** A BLOCK has no expiry, but the store that holds
  it can lose it: the memory of a standalone server ends with the server, and a Redis that was emptied or replaced has no
  flags. The block was then only in the database (`ctxa_blocked_user`) and the user went on. Every application, in
  standalone or distributed mode and with or without a `spring.application.name`, now writes again at its start, before
  the web server takes a request, each block its own database holds in force (every recorded block that is not
  resolved) where the store has none. A block an administrator released is not written, a flag the store still has is
  left as it is, and without a record of blocks (no `contexa-iam`) nothing is written. If the database cannot be reached
  the application starts all the same, `Restrictions could not be restored` is logged at ERROR and the write is tried
  again for about four minutes. **Check:** in standalone a restart still ends a CHALLENGE, an ESCALATE and the ALLOW held
  for a user, the learning quarantine and the rest of what is kept in memory, and a BLOCK nothing recorded (an agent's,
  or any BLOCK without `contexa-iam`); the start says so at WARN. A user blocked before the restart is blocked after it
  when the line `Restrictions without an expiry were restored` is logged at INFO.
- **A role, permission or action name no longer changes the condition it is written into.** A policy condition wrote
  names into SpEL as they were, so a quote in a name ended its literal: `O'Neil` made a condition that broke the save
  (500), and `X') or true or hasAuthority('Y` made one that was always true. Every condition built from a role, a
  permission, a CRUD action, an AI action or a template value now writes the name as one literal, its quotes doubled,
  and asks for exactly that name; the policy matrix, impact analysis, duplicate check, editing of a policy and the
  affected-policy warnings read such a name back as it is. Stored conditions are not changed, and a name with no quote
  is written as before. **Check:** a CRUD action or a template value carrying SpEL is now saved as an inert value instead
  of being refused.
- **A locked or disabled account no longer signs in by e-mail code or with a passkey.** Spring's one-time token and passkey providers took the account the code or the key named as it was, so a locked or disabled account signed in by code alone (`.ott()`) and the sign-in's success then lifted the lock. Both now refuse such an account as the password does, alone and as a step of the MFA flow, and a refused attempt leaves the lock as it was. No code is made or mailed for such an account, and the answer to asking is the one any other name gets. A lock in force therefore also stops a step-up by code until it ends.
- **A sign-out that carries only the access token now ends it.** With the HEADER transport a `POST /logout` with the `Authorization` header alone was answered `LOGGED_OUT` while the access token and its refresh token went on working. The sign-out now ends the authorization the authorization service finds for that token, both of its tokens. A token that is no live one of the server ends nothing and is answered as before.
- **A person's token is exchanged by the rules of its renewal.** With token exchange on, an agent exchanged the token of a person under a BLOCK, CHALLENGE or ESCALATE, or of a locked or disabled account, and the exchanged token answered in the person's name. The exchange is now refused as the renewal is: `access_denied` while a decision in force stops the person (whatever it asks, since the agent cannot answer a challenge in the person's place), `invalid_grant` for an account that is gone, disabled or locked. In the report-only mode the decision does not refuse it, as it does not refuse the renewal.
- **An exchanged token gets no scope the exchanged token does not hold.** Spring checked the scopes an exchange asks for against the client only, so an agent holding `reports.write` exchanged a person's `read` token for `reports.write`. A scope beyond the scopes both the client and the exchanged token hold is now refused with `invalid_scope`. **Check:** a scope an agent asks for in a person's name must be one `contexa.auth.oauth2.scope` gives the person's tokens (it is `read` by default), and the internal client keeps the scopes of its first start.
- **A suspended agent registered in a tenant no longer gets tokens.** A token Contexa issues names no tenant, and the token endpoint and the resource server looked such a client up in the single-tenant deployment only, so an agent registered with a `tenantId` went on getting its own tokens and exchanged ones after it was stopped, and the delegation it held was not read at the exchange. A token that names no tenant is now refused when the client is suspended in any tenant, a token that names a tenant also when the single-tenant registration is suspended, and the token endpoint reads the agent and its delegations in the tenant that registered the client. The in-memory and database registries answer alike.
- **An exchanged token no longer outlives the person's sign-in.** An agent could exchange the token it got by exchange again, as often as it liked, and keep speaking in the person's name after the person signed out. A token issued by token exchange is now refused as the subject of another exchange (`invalid_grant`), an exchanged token ends no later than the token it was exchanged from, and a person's sign-out ends the tokens agents got by exchanging the person's tokens, unless a delegation the person gave that agent holds: the delegation then governs them, as it does every request of the agent. An agent that signs out its exchanged token ends that token only. A forced sign-out (a password change, a disabled account, a risk signal) ends every token of the person as before.
- **An agent holding an administrator's token can no longer use the console.** The console's pages and API under
  `/contexa/admin/**` now answer `403 AGENT_NOT_ALLOWED` to every request the bridge reads as an agent's, before any of
  them acts: the agents' stops and releases, the kill switch, agent registrations and their secrets, learning, users and
  policies answered such a request as they answer its administrator. A person's request with the same account is
  unchanged. **Check:** an integration that let an agent call the console's API calls it with a person's sign-in or with
  a client that is no agent.
- **A console session under a CHALLENGE or an ESCALATE of its own only reads the block list.** The block list and the
  agents' stops stay open to every console session so that a restriction can be lifted, and only a BLOCK kept a session
  to reading there: a session under a CHALLENGE or an ESCALATE of its own could lift someone else's BLOCK or CHALLENGE,
  release agents and use the kill switch. Such a session now reads and changes nothing, and the refusal is audited, until
  it passes the console's step-up (`/contexa/admin/blacklist/step-up`), which answers its CHALLENGE in that session only,
  or until the ESCALATE is decided. **Check:** an administrator under a CHALLENGE passes the step-up before changing
  anything there.
- **A change of a user no longer takes the console's last administrator.** Changing a user's groups or direct roles,
  disabling the user or deleting it, on the user's page or in the access center, is refused with 409 and nothing of it
  is kept when the user is the last enabled account of Contexa's own holding `ROLE_ADMIN` (directly, through a group or
  through the role hierarchy). Changes of roles, groups or the hierarchy themselves are not checked. **Check:** a console
  left without an administrator is recovered by setting `contexa.iam.seed.admin.password` with a
  `contexa.iam.seed.admin.username` and `contexa.iam.seed.admin.email` that no account has and restarting: the start
  creates that administrator in the administrators group and never changes an existing account.
- **The console no longer shows or keeps the value a session's cookie carries.** The tracked sessions
  (`ctxa_active_sessions`) kept each session under its raw identifier, and the session list showed it in full, wrote it
  to the CSV export and invalidated by it, so an administrator could take another person's session. A session is now
  kept, shown, exported and invalidated by its reference (`sid-` and 24 hexadecimal digits, as the audit names it). The
  rows of an existing database move to their references at the next start, and a session forced out before stays out.
  **Check:** the CSV column `Session ID` is now `Session Reference`; a call that invalidates a session by its raw
  identifier still works.
- **A waiting agent mails its person once.** While a confirmation of an agent waits for its accountable person, a further
  request of the same agent, stopped by the gate or asked by the agent itself, waits as before but reaches the person on
  the confirmations page and the console only, and so does its refusal when no one answers it in time. Within its call
  limits an agent could otherwise send a mail per request, up to 120 a minute for a delegation.
- The confirmation page and its list now say whether the agent's request has a body and how large it is, or that the
  agent named a body by its hash only; the body itself is never kept. The size is kept in
  `ctxa_agent_confirmation.body_bytes`, which an existing database gains at the next start. **Check:** a database whose
  Contexa schema is managed by its own migrations adds
  `alter table ctxa_agent_confirmation add column if not exists body_bytes bigint;`. A confirmation kept before shows its
  size as not recorded.
- **A blocked sign-in no longer says how close it came.** The `403 AUTHENTICATION_BLOCKED` answer carried the risk
  score, the reason, the user name and a contact address of no one (`security@example.com`); it now carries the status
  and a general sentence. The log line keeps the three, and the audit now records them (`AUTHENTICATION_FAILURE`,
  decision `BLOCK`, with the risk score). A failure of the MFA flow answers "An error occurred during MFA processing.
  Please sign in again." instead of the exception's own text, which stays in the log and the audit. **Check:** a client
  that read `riskScore`, `reason`, `username` or `supportContact` from that answer reads `status`, `blocked` and
  `message`.
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
  (`ctxa_bridge_user_profile.pending_email`). A user who proves the address on record, with its code or a passkey, has
  what waited for the proof answered and gets a code at the address waiting; the address takes its place only once that
  code is entered in the same session, so an address a thief left waiting is not taken at the owner's next proof. A code
  of the new address answers no CHALLENGE. The first real address of a copy that had a made-up one goes in at once, as
  before, and an address an administrator enters on the user's page of the console now stands. The column is added to an
  existing database at the next start. **Check:** a user who changed the address enters, after the step-up, the code
  that went to the new address; a user who can read neither the old mailbox nor answer with a passkey gets codes at the
  new address once an administrator enters it in the console.
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

- **Cancelling an MFA sign-in is answered at once, however many cancel together.** Each cancel handed a task to the
  shared executor that slept five seconds and then released the cancelled flow. Past the executor's ten threads and
  its queue of a hundred the task ran on the request thread: of 300 cancels sent together 240 were answered after
  four seconds or more (half after five, the last after ten), and the executor's other work, the saving of audit
  records, waited behind the sleeping tasks. The flow is now released in the request, once its answer is written.
  A later request of a cancelled flow is answered as before (`400 MFA_SESSION_INVALID`). **Check:** 300 and 1000
  cancels sent together are all answered within 0.2 seconds.
- **A verification submitted too late says so.** A code submitted after the time of its challenge
  (`contexa.auth.mfa.challenge-timeout-ms`, five minutes) ends the sign-in, and was answered by an error of the
  container: `403 {"error":"Forbidden"}`, with nothing a page could tell the person. The same went for a submission
  past the attempts allowed, in a state that takes none, or for a factor without a filter. These are now answered in
  the form of the flow's other answers, with a code and a message: `MFA_SESSION_EXPIRED`,
  `MFA_RETRY_LIMIT_EXCEEDED` (both with `redirectUrl`, the sign-in page of the flow), `MFA_INVALID_STATE` and
  `MFA_FACTOR_MISCONFIGURED`. The status codes and what happens to the sign-in are unchanged.
- **After an MFA sign-in the browser goes back to the page it asked for.** A request for a protected page is kept
  while the browser is sent to sign in, and Spring Security keeps it with a full address (`http://host/path?query`).
  The sign-in handlers of Contexa refused every address that names a host, so they refused every kept request: after
  an MFA sign-in, with the session state or the token state, and after a REST sign-in with the session state, the
  browser went to the default page and never back. A single form flow, which Spring Security answers, was not
  affected. The handlers now follow the path and the query of the kept address, so the browser stays on the site it
  signed in on whatever host that address names; an address a browser reads as another site (`//host`) and the
  requests a browser makes by itself (`/favicon.ico`, `/.well-known/`) are still not followed. Without a kept
  request the browser goes where it went. **Check:** ask for a protected page without a sign-in, complete the MFA
  sign-in, and `redirectUrl` of the answer is that page (`/` before).
- **The address after a sign-out that an application names is used, with the session state.** A flow with
  `.session(...)` wrote its own address after the application's settings, so a `logoutSuccessUrl(...)` or a
  `logoutSuccessHandler(...)` in `global(...)` or in the flow's `logout(...)` option was dropped without a word, and
  every sign-out went to `/contexa/admin/login` (to `<prefix>/mfa/login` for an MFA flow with a prefix). That address
  is now a default, given before the application's settings: what the application names is where the browser goes,
  and without one it goes where it went. The address of the sign-out itself stays `/logout` (`<prefix>/logout`): the
  Zero Trust filters and the filter of an unfinished MFA let a restricted session through to that address, so a
  `logoutUrl(...)` of the application is not used. With the token state the answer after a sign-out is still the
  `contexaOauth2LogoutSuccessHandler` bean's. **Check:** with `form(form -> form.logout(l ->
  l.logoutSuccessUrl("/bye")))` and `.session(...)`, `POST /logout` answers 302 to `/bye`.
- **A flow with `authorizeStaticPermitAll(...)` starts next to rules that end with `anyRequest()`.** The static paths
  of a flow are added as authorization rules after the rules of the global customizer, and Spring Security takes no
  rule after `anyRequest()`: with the usual `authorizeHttpRequests(a -> a....anyRequest().authenticated())` in
  `global(...)` the application did not start ("Can't configure mvcMatchers after anyRequest"). Where the rules are
  closed that way, the static paths are now opened ahead of the rules, and every other request is decided by the
  rules as they are. Where the rules are left open, nothing changes: the static paths stay rules after the
  application's own, so an earlier rule of the application still decides a path both match. **Check:** with
  `anyRequest().authenticated()` in `global(...)` and `form(form -> form.authorizeStaticPermitAll("/assets/**"))`,
  the application starts, `GET /assets/app.css` is answered without a sign-in, and a protected page still asks for one.
- **`mfa.policyProvider(...)` decides for its flow.** The DSL took the provider and nothing asked it: every decision
  of every MFA flow came from the provider bean, so a flow that named a stricter or a lighter policy got the default
  one. The provider bean now hands the four questions of a flow that names its own provider to that provider (whether
  factors are needed, the next factor, whether a factor is available, how many are required), and the AI adaptation
  is not put on top of its answer. A provider written around the bean (ask the default, then tighten the answer) gets
  the bean's own answer and is not handed its own question again. A flow that names none is decided as before.
  **Check:** an MFA flow with `policyProvider(...)` whose provider answers that no factor is needed completes the
  sign-in at the password step.
- **The generated sign-in page of a REST flow is at the address the flow signs in at.** The page was fixed at
  `/api/login` and posted there. A flow with `rest(rest -> rest.loginProcessingUrl("/api/auth"))` showed the page at
  the old address, where its POST met 404, and nothing at the new one. The page is now shown at, and posts to, the
  flow's `loginProcessingUrl`. **Check:** with `loginProcessingUrl("/api/auth")`, `GET /api/auth` shows the page
  and `GET /api/login` is 404.
- **A `formLogin(...)` of the global customizer that a form flow replaces is said at the start.** Spring Security
  keeps one form login per chain, and a `form(...)` flow puts its own in the place of the one written in
  `global(...)`: its `loginPage`, `failureUrl` and the rest were dropped without a word. The behaviour is the
  same, and the start now logs a warning that names the flow and says to write the settings in the flow
  (`form(form -> form.loginPage(...))` or `form.rawFormLogin(...)`).
- **An application with a user store of its own signs its accounts in at Contexa's form sign-in.** When the
  application has exactly one `UserDetailsService`, that store serves the sign-in Contexa owns, and its accounts are
  whatever `UserDetails` it returns. Contexa's password provider took every account for one of its own and failed on
  such an account with a class cast: 500 at every sign-in. The account now signs in as it is. **Check:** an
  application with an `InMemoryUserDetailsManager` bean and a form flow with the session state signs its user in
  (302, and the application sees the user's name); before, 500.
- **A mail server that answers slowly no longer stops every sign-in.** The mail of a sign-in is sent on the thread of
  the request that asked for it, and JavaMail waits without end where no timeout is set. With a mail server that greeted
  one connection a second, 400 requests for a code at once held every request thread: 89 were answered and 311 got no
  answer in 90 seconds, and the application did not answer its health check for the whole of that time. At most
  `contexa.auth.ott.email-max-concurrent-sends` (64) mails are now being sent at one time, a request beyond them waiting
  `contexa.auth.ott.email-send-wait-seconds` (5) for a place and then failing as an undelivered mail does (500 with
  `contexa.auth.ott.fail-on-email-error=true`, the default). The mail itself goes out with the application's own mail
  settings. A limit of time on the steps of the SMTP conversation is set only on request, with
  `contexa.auth.ott.email-smtp-timeout-seconds` (0, none): the mail sender is the application's, so a value is written
  into that sender where `spring.mail.properties.mail.smtp.*timeout` names none and bounds the application's other mail
  too. A first form of this fix set ten seconds by default; a mail server that answered after twelve then failed the
  code it had delivered before (500 after ten seconds), so the default is none. **Check:** against the mail server that
  greets one connection a second all 400 requests are answered (79 mailed as the server takes them, 321 refused after
  their wait for a place) and the health check fails for the first four seconds only; a mail server that answers after
  twelve seconds delivers the code after twelve seconds; on a mail server that keeps up 1000 accounts sign in at once
  as before.
- **A code request with no code in it counts as a failed attempt instead of stopping the sign-in.** The submission was
  put on record before the request was looked at, and a request with a missing, empty or blank `token` was then passed
  on by the code filter: the answer was 404, the flow waited for a verification that never ran, the right code got 429
  for ten seconds and after that the flow was invalid. Such a request is now a failed attempt of the factor (401, one
  attempt counted) and the right code completes the sign-in.
- **The same code sent twice under one request id is verified once.** With an `X-Request-Id` (or
  `X-MFA-Request-Id`) a second submission was answered with the outcome of the first, "accepted", and went on to the
  code filter as well: of ten requests at once none completed and one got 500. The repeated submission is now told to
  retry (429, `VERIFICATION_RUNNING`) and one request completes.
- **A factor selection that names no factor of the flow leaves the sign-in where it is.** The flow was moved to the
  selection state before the name was checked, so one request with an unknown name (`MFA_TOTP`, `OTT`) took the
  challenge in progress away: the code already mailed was refused (400), and asking for another did not bring the flow
  back. The name is checked first; the selection is refused (400) and the code still completes the sign-in.
- **A sign-in by mail code alone goes on to the page that takes the code.** After the code was requested the browser
  was sent to `/mfa/ott/code-sent?...`, a page of the MFA pages that a single mail-code flow does not have (404). It
  now goes to the flow's own page: the one its DSL names with `defaultSubmitPageUrl(...)`, and `/login/ott/verify`
  where it names none; the name asked for is not in that address. An application that named a "code sent" address of
  its own (`contexa.auth.urls.factors.ott.code-sent`, anything but the default) has a page there, and is sent to it as
  before, with the parameters it had (`email`, `type`, `flow`, `repository`). **Check:** with that address set to a
  page of the application the browser goes there and the page answers; with none set it goes to `/login/ott/verify`.
- **A failed password step of an MFA flow goes back to that flow's sign-in page.** A form submitted without the
  script was redirected to a fixed `/login?error=...`, which an MFA flow does not have (its page is `/mfa/login`, under
  the flow's prefix): 404. The redirect and the `nextStepUrl` of the JSON answer now name the address the flow's DSL
  gives with `failureUrl(...)`, as it is, and the flow's own sign-in page with `?error=...` where it gives none; until
  now a `failureUrl` of an MFA flow's password step was not used at all.
- **A request sent to the addresses of one MFA flow while the sign-in in progress belongs to another is refused.**
  With two MFA flows, such a request was passed on unchecked to the other flow's own filters, which verified the code
  and then failed on the state (500). It is refused with 400 `MFA_FLOW_MISMATCH`; the sign-in in progress is untouched
  and its code still works at its own address.

- **Turning the thinking of an Ollama model off no longer throws away the call's options.** When a model matched
  `contexa.llm.model-capabilities.ollama.disable-thinking-patterns` (or the call set `disableOllamaThinking`),
  `ProviderAwareChatOptionsFactory` read `ThinkOption.ThinkBoolean.DISABLED` as an enum constant. Spring AI 1.1 defines
  `ThinkBoolean` as a record with static constants, so the lookup threw `ThinkBoolean is not an enum class`; the factory
  logged an error and fell back to the model's default options, and the call ran without its runtime model, sampling and
  answer limit (`numPredict`) and with the thinking on. The constant is now read as a static field, and a thinking that cannot
  be turned off is logged as a warning while the rest of the options are kept. A setup that names no pattern was not affected.

- **A repeated name or an empty element in the authorities of a header or a request attribute no longer loses the request's
  bridge.** `HeaderAuthBridge` and `RequestAttributeAuthBridge` read the comma-separated authorities with
  `Set.of(value.split(...))`, which throws on a repeated element: `ROLE_USER, ROLE_USER` and `ROLE_A,,,ROLE_B` raised an
  `IllegalArgumentException`, and `BridgeResolutionFilter` then dropped every stamp of that request (the request itself went
  on). A single empty element (`A,,B`) did not throw but became an authority named `""`. Each name is now read once, in the order
  it came, with the spaces around it trimmed, and an empty element is skipped. These two readers are reached only when the
  header or request-attribute bridge is turned on and the SecurityContext does not name the principal first, so a default
  setup was not affected.

- **An identical strategy request that is already running is refused, as the documentation says.** `AINativeProcessor` took the
  lock of a strategy under the node name as its owner, and the lock lets its own owner in again. The node name is
  `contexa.security.plane.agent.name`, `SecurityPlaneAgent-1` unless it is set, the same on every node, so the second identical
  request was always let in and `Strategic operation conflict` never came, in standalone mode or in a cluster. Each run now takes
  the lock under an owner of its own (the node name and a random part), once for each subscription of the `Mono` or `Flux` it
  returns, and gives it back when it ends, fails or is cancelled. The refusal is a `StrategicOperationConflictException` (an
  `AIOperationException`). `POST /contexa/admin/api/ai/policies/generate` answers 409 for it instead of 500, and resource naming
  and condition template generation, which answered any failure with default names and templates, now stop instead of saving
  defaults beside what the running request saves. A lock store that cannot answer is no longer reported as a conflict: the call
  fails with `Strategic lock unavailable` and nothing runs without the lock. The lock lasts at most 30 minutes, so a node that
  stops while holding it in distributed mode keeps an identical request out until it expires.

- **SHADOW now decides, remembers and learns as ENFORCE does, and applies nothing.** SHADOW ended before the final decision was stored, so the ALLOW that answers a user for the next minutes did not exist and every request of a user was analysed again: a 1,000-user trial asked the model 2.15 times as many questions as ENFORCE (2,145 decisions for 1,000 users), and a trial in SHADOW cost that much more than the same traffic in ENFORCE. SHADOW also learned nothing of a user's usual behaviour (baseline, work profile, role scope, decision documents), so the model judged a user it had allowed as new again, and the statistics of a trial were not those of ENFORCE. SHADOW keeps its decisions in a memory under keys of its own (`shadow::`), with the rules and lifetimes of the store ENFORCE uses; only the counting of decisions reads it (the skip of a user already decided, the queue recheck, the synchronous `@Protectable` service, the action an event records). What enforces a decision keeps reading the repository, which holds no decision of SHADOW, so nothing a shadow decision says can stop a user, and a switch to ENFORCE starts without the decisions of the trial. An ALLOW of SHADOW is learned and its context observations and decision document count as ENFORCE's do. What restricts the user is still not done: no block, no challenge, no held request, no narrowing of an agent's scope, no risk signal. The data of a deleted account leaves the memory with the rest. While the store that records decisions refuses writes, SHADOW suspends new analysis of the user's context as ENFORCE does (the model is asked once for each user, not once for each request: 12 questions, not 72, for 12 users asking six times). **Check:** the same 1,000-user test gives 1,000 decisions (ALLOW 900, BLOCK 50, CHALLENGE 50) in both modes, the same keys and the same decision documents; what only ENFORCE leaves is the block, the stopped requests, the challenge sessions and the enforcement result of the audit record (`OBSERVED_ONLY` in SHADOW).

- **Failed sign-ins from one new address, at the same moment, no longer fail a database statement each.** The first failure of an address inserts its row in the table of login attempts per address; failures that came together all found the row missing and all inserted, and every one that lost the unique key left a failed statement in the database log and an `UnexpectedRollbackException` on the commit of the caller (seen with 1,150 sign-ins in seven seconds in the full mode). The failures of one address now take turns before the insert (a lock chosen by the address) and the later ones see the row the first made; the loss of a race between servers is still taken as "the row exists" and the failure is counted again. The upserter no longer swallows the key violation inside its own transaction, which had left that transaction rollback-only.

- **A call that timed out in the middle of the line at a model server stopped every call behind it.** `ModelServerGate` kept its
  waiters in a line and took a leaver out by equality; waiters of the same kind, model and line are equal, so a waiter in the
  middle that timed out or was interrupted took out the first one instead and left its own entry at the head with no thread
  behind it. Admission compares the head by reference, so no call went in until the next timeout (about 175 s with the server
  idle, measured on a slow model). A waiter now takes out itself.
- **Recording a timeout failed with `ConcurrentModificationException` on a slow model.** The metadata of an analysis attempt is a
  synchronized map, so that the analysis can write while the budget thread reads it; five steps replaced it, when they made it
  writable, by a plain map, and the two threads met in it (34 of 128 timeouts on a slow model). They keep the guarded map now.

- **A console form that fails with a message now shows the message.** A role a hierarchy still names, a group role that
  does not exist, a hierarchy that exists already, a user name taken and a password the policy refuses each answered an
  error page (`UnexpectedRollbackException: Transaction silently rolled back because it has been marked as
  rollback-only`) instead of the message: the controller methods of the users, roles, groups and role hierarchies
  opened a transaction of their own, the service they called joined it, and the service's exception marked it for
  rollback before the controller caught it. These methods no longer open a transaction, the services keep theirs, so
  the refusal is rolled back there and the page the person returns to says why. Nothing else of them changes.
- **A role that accounts or groups still hold is refused with who holds it, and a group with role permissions can be
  deleted.** Deleting a role an account holds failed in the database with a foreign key nobody can read, and deleting a
  role a group holds took it from the group without a word. The role is now refused, before anything is changed, with
  how many accounts and groups hold it and the order to revoke it from them first. Deleting a group failed in the
  database when roles had been given to it in the access center with their permissions; the group's permissions now go
  with the group, as its memberships and roles do. **Check:** a role that groups hold can no longer be deleted until it
  is taken from them, and the refusal of the console's last administrator on deleting the administrators' role is now
  this one.
- **The policy center answers a policy it refuses or fails to write instead of ending in a failed commit.** Making a
  policy from the center, a quick policy, a rollback to a version, a batch, the migration and the cleanup of policy
  expressions and the reset of resources each opened a transaction that the services they call joined; a callee that
  refused or failed marked it for rollback before the center caught what it threw, and the commit at the end raised
  `UnexpectedRollbackException` in place of the answer. The calls that answer a failure now end in a transaction of
  their own, the migration and the cleanup roll back as a whole, and the items of a batch (and the resources of a reset)
  are written one transaction each, so an item the database refuses is answered as that item and the others are written.
- **A permission that roles were given to groups or accounts with is refused with where it is used.** Deleting it failed
  in the database with a foreign key nobody can read; it is now refused, before anything is changed, with how many group
  and account assignments carry it and the order to revoke it from them first.
- **A policy form that is refused now shows the refusal.** Creating a policy without a name, editing or deleting a
  policy that is not there, and approving a policy approved already or rejecting one rejected already each answered an
  error page (`UnexpectedRollbackException`) instead of the message, for the reason the user, role, group and role
  hierarchy forms did: the controller methods opened a transaction of their own that the service joined. The five write
  methods of the policy controller no longer open a transaction; the service keeps its own, so a refusal is rolled back
  there and the policy center's list says why. Nothing else of them changes.
- **Editing an administrator of the console no longer fails when the account keeps a group.** Saving the user form of an
  account that was an active administrator, or setting its groups in the access center, answered an error
  (`EntityExistsException: A different object with the same identifier value was already associated with the session`)
  and kept nothing whenever the account kept at least one of its groups, which is every edit that does not empty them.
  The groups were dropped and made again under the same key, and the check of the last administrator that follows reads
  the roles, which writes what is pending while the dropped row is still in the session. The groups an account keeps are
  now left as they are: only the groups dropped are removed and only the new ones are added. Accounts that were not
  administrators were not affected.
- **The permission list and the page of a permission no longer fail when a permission guards a resource.** Opening
  `/contexa/admin/permissions` answered 500 (`LazyInitializationException: Could not initialize proxy
  [ManagedResource#...] - no session`) as soon as a permission made from a resource, in the policy center's "Create
  Permission & Policy" or by defining a resource, was among those listed, and so did the page of such a permission, so
  the warning before it is deleted could not be opened from the list. The screens read the resource of each permission
  after the session of the query had ended. The permission queries now read the resource together with the permission:
  in the list, in a search, on the page of one permission and in the permission an update hands back, which the page is
  shown from the cache. Permissions that guard no resource were not affected.
- **A policy made for a role whose name does not start with `ROLE_` now lets that role's people through.** A role named
  `sales` gives its holders the authority `ROLE_SALES` (`ROLE_` and the name in capitals), but the policies made for a
  role, in the policy center's quick panel, by a business rule and by the automatic policy of a role, asked for the
  name of the role itself, so nobody passed while the policy matrix showed the role as allowed. Those conditions now
  ask for the authority the role gives, written by one rule (`RoleAuthority.authorityOf`), and the policy matrix, the
  referential check of an AI policy, the roles shown when a business rule is opened for editing and the warning before
  a role is deleted read that same name. A role whose name starts with `ROLE_` is asked for as before, and stored
  conditions are not changed. **Check:** a policy made earlier for a role without the prefix still asks for the bare
  name and lets nobody through: make it again, or write its condition with `ROLE_` and the name in capitals.
- **A role whose permissions guard no resource no longer ends its automatic policy in an error.** The policy that
  follows a role's permissions applies to the resources those permissions guard, and a policy needs at least one. A
  role holding only permissions with no resource raised "at least one target is required" in the background and made no
  policy. Such a role now has no automatic policy to make, and the log says so at INFO. A role with a resource gets its
  policy as before, and a role that had its policy and loses its last resource keeps that policy updated.
- **The policies listed before a role or a permission is deleted are the ones that name it.** The list searched the
  conditions for the name as a part of any text, so the role `O` listed the policies of `ROLE_OTHER`, and a `_` or `%`
  in a name matched other names. It now lists the active policies with a condition literal exactly equal to the name,
  each policy once: a role is searched by the authority it gives and by its own name, the form older conditions have.
- **The log says again which partitions the security event consumer holds.** Since the consumer's decided-record listener replaced the container's own, the lines `partitions assigned`, `partitions revoked` and `partitions lost` were no longer written, and a runbook or a check that waits for the first of them found nothing. The listener writes the three lines itself, with the consumer group in front, as Spring Kafka does.
- **A role's policy is made after the role is saved.** The policy that follows a role's permissions was made on another
  thread as soon as the change was announced, before it was committed: a new role was not found ("Role not found for
  synchronization") and a changed one was read with its old permissions. It is now made after the commit, and a change
  that rolls back makes none.
- The role hierarchy diagram shows each role's own name: `R&D` no longer reads `R&amp;D`, a name with `<` is no longer
  cut, two names such as `R&D` and `R_D` are no longer drawn as one node in the confirm dialog, and a diagram that cannot
  be drawn shows its error state.
- Saving a menu with some of its fields keeps the others: a request without a parent no longer moves the menu to the top.
- The cancel button of the delete dialog, the policy center's loading text and two Korean sub-menu labels of the quality
  inspection show their text instead of their message key.
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
- The start names Redis Cluster at ERROR, which this release does not support, and, in standalone, what a restart ends:
  the decisions kept in memory, while a BLOCK the block record holds in force is written again.
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
  again: calls that waited behind a decision cost that decision and not one each.
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
- **The list of people with a stored baseline no longer grows with every person ever seen.** The index of users (and of
  organizations) in Redis was a set that every save added to and that was trimmed only when the users were counted
  (off by default) or a person's data was deleted, so with a retention of days it kept every person long after the
  baseline had expired. It is now ordered by when each baseline expires, and every save drops the entries that have
  expired. The set an earlier version left is moved into it the first time a server of this version saves, counts or
  lists (a baseline still stored keeps the time it has left) and is then removed; nothing is to be set up and the
  baselines are not changed. An earlier-version server that still runs beside a new one goes on adding to the old set;
  those people are indexed again at their next save.

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

- **ASEP is registered by one auto-configuration.** The `contexa-identity` module listed an auto-configuration of
  its own, `io.contexa.contexaidentity.security.core.asep.autoconfigure.AsepAutoConfiguration`, next to
  `io.contexa.autoconfigure.identity.IdentityAsepAutoConfiguration` of `contexa-autoconfigure`: the same beans
  twice, one set skipped by its conditions. The module's class is removed and the beans are the same as before. An
  application that names the removed class in an exclusion or an import names
  `io.contexa.autoconfigure.identity.IdentityAsepAutoConfiguration` instead.
- **The action in force of a user is read in one script instead of three round trips.** A protected request asks for it seven times,
  and each ask read the BLOCK flag, the analysis and the held CHALLENGE one after the other, about twenty of the thirty or so
  commands a request waits for on its own thread. One script on the shared connection reads the three; what is decided from them
  is unchanged, an analysis in an earlier form and a store that refuses scripts are read the old way, and a store that does not answer
  keeps the restriction read last in force. A quiet server answers a protected call in 26-29 ms instead of 34 ms.
- **The prompt token estimate weighs each character once, and an ASCII character without a script lookup.** A flight recording of
  1,000 users signing in at once put 27% of all CPU samples of the server in the weight of a character: each looked its script up four
  times, and the system and user prompt were counted again as one text. The numbers are the same (a test keeps the plain count and
  compares); the estimate is observation only.
- **A request that repeats an analysis already in line takes no second place in the line.** A request answered by the
  decision that waits ahead of it costs that decision and no turn of its own (PR-82), yet each took a place, up to eight for a
  user, and a burst of new users filled the line (3,276 places at 1 GB) with requests that were then skipped, so that the first
  decisions of other sessions were turned away: 3,575 events were left unanalysed with a remote model and 8,734 with a local one. A
  request of a session in line is now kept in its session at once, and the places go to the first decisions of other sessions.
  Only a repeat from the same context is kept: a decision is bound to its context, so a request that comes from another
  address or browser is analysed, and so is an event that returns to be tried again after a failed analysis.
- **The analyses that run at once follow what the model servers can serve.** A call waits at a gate at most until the event's
  budget, so more analyses than a gate serves within it only fail at the budget. A gate now measures how long a chat call holds
  its slot, and the analyses that run at once are slots x budget / (six chat calls x call time x 1.5), never fewer than two for
  each slot and never above `analysis-stripes`; a server that takes no chat call (an embedding server) does not count. What
  does not run waits in the line in its order, with its budget not started.
- **The session record of a request answered by the decision in force is made off the thread of the request.** About 36 of the
  70 Redis commands of a protected call were this record, which only feeds the decisions that come later. It is made by eight
  threads, one session always on the same one so that its records keep their order; a line that is full is no lost record, the
  thread that asks makes it.

- **Contexa's thread pools give back the threads they have no work for, and the analysis actors are 64 instead of 256.** The core
  threads of a `ThreadPoolTaskExecutor`, and of a fixed pool, stay for ever: after a load of 1,000 people Contexa still held 576
  threads against the 197 of the application alone, and the analysis actors (a fixed pool of 256 with no keep-alive) were never
  ended. Every pool of Contexa now ends a thread that has had nothing to run for a minute (threads at rest after that load:
  382). The analysis actors only wait for the model, and what an analysis can use is the 64 analysis threads and the model
  server's gate, so `contexa.security.plane.agent.analysis-stripes` is 64 by default; a value you set stays as you set it.
- **The README says what Contexa adds to the JVM of the application.** Heap, process memory and threads with and without
  Contexa, the limits that bound what Contexa holds, and the Netty pool setting for servers with many cores.

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
- **Contributors: the tests that use Redis or PostgreSQL no longer fall back to `localhost:6379` and
  `localhost:5432`**, where a developer's own Redis and database usually listen. Without `CONTEXA_TEST_REDIS_PORT` or
  `CONTEXA_TEST_DB_URL` they are skipped before they connect, the tests no longer read the application's own
  `CONTEXA_DB_*` variables, and a test that empties its Redis (`FLUSHDB`) fails on port 6379 instead of running there.
  CONTRIBUTING.md shows two throwaway containers and the variables; the CI workflow now starts a Redis for these tests.

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