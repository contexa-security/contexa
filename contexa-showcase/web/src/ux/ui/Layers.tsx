import { useEffect, useId, useRef, type ReactNode, type SyntheticEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon } from './Icon';
import styles from './Layers.module.css';

/**
 * Keeps a native modal dialog in step with the screen's state: opened with showModal (focus moves inside, the page
 * behind is inert), Escape asks the screen to close it, and the focus goes back to where it was.
 */
function useModalDialog(open: boolean) {
  const dialog = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  useEffect(() => {
    const element = dialog.current;
    if (!element) {
      return;
    }
    if (open && !element.open) {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      element.showModal();
    } else if (!open && element.open) {
      element.close();
      opener.current?.focus();
      opener.current = null;
    }
  }, [open]);
  return dialog;
}

interface LayerProps {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly title: ReactNode;
  readonly children: ReactNode;
  readonly footer?: ReactNode;
}

function CloseButton({ onClose }: { readonly onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <button type="button" className={styles.close} aria-label={t('ux.action.close')} onClick={onClose}>
      <Icon name="x" size="lg" />
    </button>
  );
}

/**
 * A modal (기획안 13): only for one record picked from a list on a phone, a costly or irreversible action's
 * confirmation, and long original text. 560 or 720 wide; the actions sit at the bottom right.
 */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  size = 'md',
}: LayerProps & { readonly size?: 'sm' | 'md' }) {
  const dialog = useModalDialog(open);
  const titleId = useId();
  const cancel = (event: SyntheticEvent) => {
    event.preventDefault();
    onClose();
  };
  return (
    <dialog
      ref={dialog}
      className={styles.modal}
      data-size={size}
      aria-labelledby={titleId}
      onCancel={cancel}
    >
      <header className={styles.head}>
        <h2 id={titleId} className={styles.title}>
          {title}
        </h2>
        <CloseButton onClose={onClose} />
      </header>
      <div className={styles.body}>{children}</div>
      {footer ? <footer className={styles.foot}>{footer}</footer> : null}
    </dialog>
  );
}

/** A drawer from the start side (the menu on narrow screens) or the end side (a record's details on a phone). */
export function Drawer({
  open,
  onClose,
  title,
  children,
  footer,
  side = 'end',
}: LayerProps & { readonly side?: 'start' | 'end' }) {
  const dialog = useModalDialog(open);
  const titleId = useId();
  const cancel = (event: SyntheticEvent) => {
    event.preventDefault();
    onClose();
  };
  return (
    <dialog
      ref={dialog}
      className={styles.drawer}
      data-side={side}
      aria-labelledby={titleId}
      onCancel={cancel}
      onClick={(event) => {
        // A press on the backdrop (the dialog box itself, outside its content) closes it.
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className={styles.drawerInner}>
        <header className={styles.head}>
          <h2 id={titleId} className={styles.title}>
            {title}
          </h2>
          <CloseButton onClose={onClose} />
        </header>
        <div className={styles.drawerBody}>{children}</div>
        {footer ? <footer className={styles.foot}>{footer}</footer> : null}
      </div>
    </dialog>
  );
}

/**
 * The detail panel beside a list on wide screens (기획안 5.2): 340~400 wide, head 56, group titles 13/600, names and
 * values, two actions at the bottom.
 */
export function DetailPanel({
  title,
  onClose,
  children,
  footer,
}: {
  readonly title: ReactNode;
  readonly onClose?: () => void;
  readonly children: ReactNode;
  readonly footer?: ReactNode;
}) {
  const titleId = useId();
  return (
    <aside aria-labelledby={titleId} className={styles.panel}>
      <header className={styles.panelHead}>
        <h2 id={titleId} className={styles.panelTitle}>
          {title}
        </h2>
        {onClose ? <CloseButton onClose={onClose} /> : null}
      </header>
      <div className={styles.panelBody}>{children}</div>
      {footer ? <footer className={styles.panelFoot}>{footer}</footer> : null}
    </aside>
  );
}

/** A titled group inside a detail panel. */
export function DetailGroup({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <section className={styles.group}>
      <h3 className={styles.groupTitle}>{title}</h3>
      {children}
    </section>
  );
}
