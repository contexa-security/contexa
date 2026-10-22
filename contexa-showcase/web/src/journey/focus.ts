/**
 * Gives the focus to the screen's headline when the control that had it goes away on the same screen (a send button
 * replaced by the running run, RC-9), the way a new screen gets it (App RouteFocus): the keyboard never falls back to
 * the page itself.
 */
export function focusHeading(): void {
  const heading = document.querySelector<HTMLElement>('main h1');
  if (heading) {
    heading.tabIndex = -1;
    heading.focus({ preventScroll: true });
  }
}
