// A file's editor: markdown in CodeMirror, bound to the file's Yjs text. "- [ ]" items show as checkboxes that tick
// with a click; Alt+↑/↓ moves lines.
import { defaultKeymap } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorState, type Range } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate, WidgetType, keymap } from "@codemirror/view";
import { yCollab, yUndoManagerKeymap } from "y-codemirror.next";
import type * as Y from "yjs";

class Checkbox extends WidgetType {
  constructor(readonly checked: boolean) {
    super();
  }

  eq(other: Checkbox) {
    return other.checked === this.checked;
  }

  toDOM() {
    return Object.assign(document.createElement("input"), { type: "checkbox", checked: this.checked, className: "cm-task" });
  }

  ignoreEvent() {
    return false;
  }
}

function boxes(view: EditorView): DecorationSet {
  const found: Range<Decoration>[] = [];
  for (const { from, to } of view.visibleRanges) {
    for (let pos = from; pos <= to; ) {
      const line = view.state.doc.lineAt(pos);
      const match = /^\s*[-*+] \[([ xX])\]/.exec(line.text);
      if (match) {
        const at = line.from + match[0].length - 3;
        found.push(Decoration.replace({ widget: new Checkbox(match[1] !== " ") }).range(at, at + 3));
      }
      pos = line.to + 1;
    }
  }
  return Decoration.set(found);
}

const checkboxes = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;

    constructor(view: EditorView) {
      this.decorations = boxes(view);
    }

    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) this.decorations = boxes(update.view);
    }
  },
  {
    decorations: plugin => plugin.decorations,
    eventHandlers: {
      mousedown(event, view) {
        const box = event.target as HTMLElement;
        if (!box.classList.contains("cm-task")) return false;
        const at = view.posAtDOM(box) + 1;
        view.dispatch({ changes: { from: at, to: at + 1, insert: view.state.sliceDoc(at, at + 1) === " " ? "x" : " " } });
        return true;
      }
    }
  }
);

export function editor(parent: HTMLElement, text: Y.Text): EditorView {
  const extensions = [
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap]),
    markdown(),
    syntaxHighlighting(defaultHighlightStyle),
    EditorView.lineWrapping,
    checkboxes,
    yCollab(text, null)
  ];
  return new EditorView({ parent, state: EditorState.create({ doc: text.toString(), extensions }) });
}
