import { BrowserRouter } from 'react-router-dom';
import { UxApp } from './ux/UxApp';

/**
 * The demo's application: the UX-R1 screens in their frame (src/ux, 구현계획서 I-2). The old screens' files stay in the
 * source without an address until the user removes them (DEC-1); their old addresses lead to the new places.
 */
export default function App() {
  return (
    <BrowserRouter>
      <UxApp />
    </BrowserRouter>
  );
}
