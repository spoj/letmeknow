// A file's editor: markdown in CodeMirror, bound to the file's Yjs text. "- [ ]" items show as checkboxes that tick
// with a click; Alt+↑/↓ moves lines. Images the file links show below their line; pasting or dropping one uploads it
// and inserts its link.
import { defaultKeymap } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorState, type Range, StateField } from "@codemirror/state";
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

/** How the editor reaches the group's images: a link's image as a data: URL, and uploading one, which gives its link. */
export type Images = { show: (link: string) => Promise<string>; attach: (bytes: Uint8Array) => Promise<string>; fail: (error: unknown) => void };

/** What a blob may hold: the relay's 1 MiB cap, less what sealing adds. */
const MAX_BYTES = 1024 * 1024 - 28;
const LONGEST_SIDE = 1600;

class Picture extends WidgetType {
  constructor(
    readonly link: string,
    readonly images: Images
  ) {
    super();
  }

  eq(other: Picture) {
    return other.link === this.link;
  }

  toDOM(view: EditorView) {
    const box = Object.assign(document.createElement("div"), { className: "cm-image" });
    box.style.padding = "4px 0";
    this.images.show(this.link).then(
      src => {
        const img = Object.assign(document.createElement("img"), { src, onload: () => view.requestMeasure() });
        Object.assign(img.style, { display: "block", maxWidth: "100%", maxHeight: "24rem" });
        box.append(img);
      },
      error => {
        box.textContent = `image unavailable: ${error instanceof Error ? error.message : error}`;
        box.style.opacity = "0.6";
      }
    );
    return box;
  }
}

function pictures(state: EditorState, images: Images): DecorationSet {
  const found: Range<Decoration>[] = [];
  for (const match of state.doc.toString().matchAll(/!\[[^\]\n]*\]\((lmk:[0-9a-f]{64}#[0-9a-f]{64})\)/g)) {
    const end = state.doc.lineAt(match.index).to;
    found.push(Decoration.widget({ widget: new Picture(match[1], images), block: true, side: 1 }).range(end));
  }
  return Decoration.set(found, true);
}

/** An image scaled to at most LONGEST_SIDE pixels, as WebP (JPEG where the browser cannot), smaller until it fits a blob. */
async function shrink(file: Blob): Promise<Uint8Array> {
  const bitmap = await createImageBitmap(file);
  for (let side = LONGEST_SIDE, quality = 0.9; ; side *= 0.75, quality = Math.max(0.5, quality - 0.1)) {
    const scale = Math.min(1, side / Math.max(bitmap.width, bitmap.height));
    const canvas = new OffscreenCanvas(Math.max(1, Math.round(bitmap.width * scale)), Math.max(1, Math.round(bitmap.height * scale)));
    canvas.getContext("2d")!.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    let encoded = await canvas.convertToBlob({ type: "image/webp", quality });
    if (encoded.type !== "image/webp") encoded = await canvas.convertToBlob({ type: "image/jpeg", quality });
    if (encoded.size <= MAX_BYTES) return new Uint8Array(await encoded.arrayBuffer());
  }
}

/**
 * Uploads the images among `files` and inserts their links on lines of their own, after the line at `at`, so that a
 * drop never splits a link; false if there are none, so the editor handles the event.
 */
function insertImages(view: EditorView, images: Images, event: Event, files: FileList | undefined, at: number): boolean {
  const chosen = [...(files ?? [])].filter(f => f.type.startsWith("image/"));
  if (!chosen.length) return false;
  event.preventDefault();
  for (const file of chosen) {
    const alt = file.name.replace(/\.[^.]*$/, "").replace(/[[\]]/g, "");
    shrink(file)
      .then(images.attach)
      .then(link => {
        const line = view.state.doc.lineAt(Math.min(at, view.state.doc.length));
        view.dispatch({ changes: { from: line.to, insert: `${line.length ? "\n" : ""}![${alt}](${link})` } });
      })
      .catch(images.fail);
  }
  return true;
}

export function editor(parent: HTMLElement, text: Y.Text, images: Images): EditorView {
  const extensions = [
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap]),
    markdown(),
    syntaxHighlighting(defaultHighlightStyle),
    EditorView.lineWrapping,
    checkboxes,
    StateField.define<DecorationSet>({
      create: state => pictures(state, images),
      update: (decorations, tr) => (tr.docChanged ? pictures(tr.state, images) : decorations),
      provide: field => EditorView.decorations.from(field)
    }),
    EditorView.domEventHandlers({
      paste: (event, view) => insertImages(view, images, event, event.clipboardData?.files, view.state.selection.main.head),
      drop: (event, view) => insertImages(view, images, event, event.dataTransfer?.files, view.posAtCoords(event) ?? view.state.selection.main.head)
    }),
    yCollab(text, null)
  ];
  return new EditorView({ parent, state: EditorState.create({ doc: text.toString(), extensions }) });
}
