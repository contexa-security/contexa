/** The two themes of the demo, each with the group that tells it (IN-6 of docs/showcase/최종화면-구현계획.md). */
export const THEMES = [
  { id: 'outside', group: 2 },
  { id: 'inside', group: 5 },
] as const;

export type Theme = (typeof THEMES)[number]['id'];
