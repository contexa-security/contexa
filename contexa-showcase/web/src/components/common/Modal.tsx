import { useEffect, useId, useRef, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './Modal.module.css';

interface ModalProps {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly title: ReactNode;
  readonly children: ReactNode;
  /** The wider size of the rule's range (960 px) for tables; 720 px otherwise. */
  readonly wide?: boolean;
}

/**
 * Every modal follows one rule (common-2): 720 to 960 px wide, at most 85% of the screen high with scrolling inside,
 * closed by its button, Esc or a click outside; focus moves to its title on open and back to the opener on close; a
 * sheet sliding up from the bottom on phones. A modal never opens another modal.
 */
export function Modal({ open, onClose, title, children, wide = false }: ModalProps) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    const element = dialog.current;
    if (!element) {
      return;
    }
    if (open && !element.open) {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      if (typeof element.showModal === 'function') {
        element.showModal();
      } else {
        element.setAttribute('open', '');
      }
      element.querySelector<HTMLElement>('[data-modal-title]')?.focus();
    } else if (!open && element.open) {
      if (typeof element.close === 'function') {
        element.close();
      } else {
        element.removeAttribute('open');
      }
      opener.current?.focus();
    }
  }, [open]);

  return (
    <dialog
      ref={dialog}
      className={styles.dialog}
      data-wide={wide || undefined}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      {open ? (
        <div className={styles.frame}>
          <header className={styles.head}>
            <h2 id={titleId} className={styles.title} tabIndex={-1} data-modal-title>
              {title}
            </h2>
            <button type="button" className={styles.close} onClick={onClose}>
              {t('modal.close')}
            </button>
          </header>
          {/* The body scrolls inside, so the keyboard reaches it even when it holds nothing to press (axe). */}
          <div className={styles.body} role="region" aria-labelledby={titleId} tabIndex={0}>
            {children}
          </div>
        </div>
      ) : null}
    </dialog>
  );
}
