/**
 * Who sends a screen's requests (docs/agent Agent중심-화면 AS-1): a person, an agent acting for a person, an agent on its
 * own credentials, or an agent signed in with its own account. The kinds are the portal's case senders, read as the
 * four the visitor is told apart by; the screens never work them out from anything else.
 */
export type Subject = 'person' | 'delegated' | 'autonomous' | 'session';

export const SUBJECTS: readonly Subject[] = ['person', 'delegated', 'autonomous', 'session'];

/** The portal's {@code ScenarioDefinition.Sender} read as a subject. */
const OF_SENDER: Readonly<Record<string, Subject>> = {
  PERSON: 'person',
  DELEGATED_AGENT: 'delegated',
  DELEGATED_RELAY: 'delegated',
  AUTONOMOUS_AGENT: 'autonomous',
  INTERNAL_CLIENT: 'autonomous',
  AGENT_SESSION: 'session',
};

/**
 * The subject of a case's sender. A case that names none is a person's (every case before agents); a sender this
 * code does not know gives none, so a new kind of sender is never told as a person by a guess.
 */
export function subjectOfSender(sender: string | null | undefined): Subject | null {
  if (sender === null || sender === undefined) {
    return 'person';
  }
  return OF_SENDER[sender] ?? null;
}

/**
 * The screens of the people's track whose requests a person sends: the attack, its evidence, the normal user and the
 * insider. The agent group's screens take their subject from the case they show (the portal's sender), so they are
 * not listed here.
 */
const PERSON_SCREENS: ReadonlySet<string> = new Set([
  '2-1', '2-2', '2-3', '3-2', '3-3', '4-1', '4-2', '4-3', '4-4', '5-1', '5-2', '5-3',
]);

/** The subject a screen of the people's track names for itself; none for the other screens. */
export function subjectOfScreen(number: string | undefined): Subject | undefined {
  return number !== undefined && PERSON_SCREENS.has(number) ? 'person' : undefined;
}

/** Whether the subject is an agent of any kind. */
export function isAgent(subject: Subject): boolean {
  return subject !== 'person';
}
