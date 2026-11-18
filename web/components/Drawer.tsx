import { useEffect, useRef, type ReactNode } from "react";

interface Props {
  open: boolean;
  label: string;
  onClosed: () => void;
  children: ReactNode;
}

/** Two animation frames, so a jump-scroll commits before the smooth scroll starts. The timer
 *  covers background tabs, where requestAnimationFrame does not run. */
const twoFrames = () =>
  new Promise<void>((r) => {
    const t = setTimeout(r, 60);
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        clearTimeout(t);
        r();
      }),
    );
  });

/**
 * Right-hand detail drawer: a modal <dialog> holding a horizontal scroll-snap track
 * (spacer, then sheet). Swiping, the close button, Escape and a tap on the dim area all
 * converge on "scroll back to the spacer"; an IntersectionObserver closes the dialog once
 * the sheet has actually left the screen, so every path animates out.
 */
export function Drawer({ open, label, onClosed, children }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const sheet = useRef<HTMLDivElement>(null);
  const closeBtn = useRef<HTMLButtonElement>(null);
  const shown = useRef(false);
  const onClosedRef = useRef(onClosed);
  onClosedRef.current = onClosed;

  const slideOut = () => scroller.current?.scrollTo({ left: 0, behavior: "auto" });

  useEffect(() => {
    const d = dialog.current;
    const s = scroller.current;
    const sh = sheet.current;
    if (!d || !s || !sh) return;

    const finish = () => {
      if (!shown.current) return;
      shown.current = false;
      if (d.open) d.close();
      onClosedRef.current();
    };
    const threshold = 1 / window.innerWidth;
    const io = new IntersectionObserver(
      (entries) => {
        const entry = entries.at(-1);
        if (entry && entry.intersectionRatio < threshold) finish();
      },
      { root: d, threshold: [threshold, 1] },
    );
    io.observe(sh);

    // Fallback for browsers without scroll-driven animations: drive the backdrop from JS.
    const onScroll = () => d.style.setProperty("--drawer-backdrop", String(Math.min(1, s.scrollLeft / sh.offsetWidth)));
    const noTimeline = !CSS.supports("animation-timeline: scroll()");
    if (noTimeline) s.addEventListener("scroll", onScroll);

    const onCancel = (e: Event) => {
      if (e.cancelable) {
        e.preventDefault();
        slideOut();
      }
    };
    const onClick = (e: MouseEvent) => {
      if (!sh.contains(e.target as Node)) slideOut();
    };
    // A non-cancelable Escape closes the dialog instantly; keep state in sync.
    const onNativeClose = () => finish();
    d.addEventListener("cancel", onCancel);
    d.addEventListener("click", onClick);
    d.addEventListener("close", onNativeClose);
    return () => {
      io.disconnect();
      if (noTimeline) s.removeEventListener("scroll", onScroll);
      d.removeEventListener("cancel", onCancel);
      d.removeEventListener("click", onClick);
      d.removeEventListener("close", onNativeClose);
    };
  }, []);

  useEffect(() => {
    const d = dialog.current;
    const s = scroller.current;
    if (!d || !s) return;
    if (open && !d.open) {
      d.showModal();
      // React does not emit the autofocus attribute, so move focus to Close ourselves.
      // preventScroll stops focus from jumping the track open before the slide-in.
      closeBtn.current?.focus({ preventScroll: true });
      // The spacer comes first, so a freshly shown drawer already sits at the closed stop.
      s.scrollTo({ left: 0, behavior: "instant" });
      void twoFrames().then(() => {
        shown.current = true;
        s.scrollTo({ left: s.scrollWidth, behavior: "auto" });
      });
    } else if (!open && d.open) slideOut();
  }, [open]);

  return (
    <dialog ref={dialog} className="Drawer" aria-label={label}>
      <div ref={scroller} className="Drawer-scroller">
        <div ref={sheet} className="Drawer-sheet">
          <button ref={closeBtn} className="Drawer-close" aria-label="Close details" onClick={slideOut}>
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </button>
          <div className="Drawer-body">{children}</div>
        </div>
      </div>
    </dialog>
  );
}
