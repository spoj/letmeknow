// A file's editor: markdown in CodeMirror, bound to the file's Yjs text. "- [ ]" items show as checkboxes that tick
// with a click; a toolbar (and Alt+↑/↓, Tab, Shift+Tab) moves and indents lines. Links show as their text, and open on a
// click, except on the line being edited. Images the file links show below their line; pasting or dropping one uploads
// it and inserts its link.
import { defaultKeymap, indentLess, indentMore, indentWithTab, moveLineDown, moveLineUp } from "@codemirror/commands";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting, syntaxTree } from "@codemirror/language";
import { EditorState, type Range, StateField } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate, WidgetType, keymap, showPanel } from "@codemirror/view";
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

/**
 * Links: `[text](url)` shows as its text, styled as a link, unless a cursor is on its line; bare URLs are links too. An
 * image the file links (`![alt](lmk:…)`) shows only as the image below its line, unless a cursor is on that line.
 */
function links(view: EditorView): DecorationSet {
  const { state } = view;
  const editing = new Set(state.selection.ranges.map(r => state.doc.lineAt(r.head).number));
  const found: Range<Decoration>[] = [];
  const link = (from: number, to: number, href: string) =>
    found.push(Decoration.mark({ class: "cm-link", attributes: { "data-href": href, title: href } }).range(from, to));
  for (const { from, to } of view.visibleRanges) {
    syntaxTree(state).iterate({
      from,
      to,
      enter: node => {
        if (node.name === "URL") return void link(node.from, node.to, state.sliceDoc(node.from, node.to));
        if (node.name !== "Link" && node.name !== "Image") return;
        const [open, close] = node.node.getChildren("LinkMark");
        const url = node.node.getChild("URL");
        if (!url || !close) return false;
        const href = state.sliceDoc(url.from, url.to);
        const shown = !editing.has(state.doc.lineAt(node.from).number);
        if (node.name === "Image") {
          if (shown && href.startsWith("lmk:")) found.push(Decoration.replace({}).range(node.from, node.to));
        } else if (close.from > open.to) {
          link(open.to, close.from, href);
          if (shown) found.push(Decoration.replace({}).range(node.from, open.to), Decoration.replace({}).range(close.from, node.to));
        }
        return false;
      }
    });
  }
  return Decoration.set(found, true);
}

const linking = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;

    constructor(view: EditorView) {
      this.decorations = links(view);
    }

    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged || update.selectionSet || syntaxTree(update.state) !== syntaxTree(update.startState)) {
        this.decorations = links(update.view);
      }
    }
  },
  {
    decorations: plugin => plugin.decorations,
    eventHandlers: {
      mousedown(event) {
        const href = (event.target as HTMLElement).closest(".cm-link")?.getAttribute("data-href");
        if (!href || !/^(https?|mailto):/i.test(href)) return false;
        window.open(href, "_blank", "noopener");
        return true;
      }
    }
  }
);

/** Makes each selected line a task, or ticks or unticks it if it is one. */
function task(view: EditorView): boolean {
  const lines = new Map(view.state.selection.ranges.map(r => [view.state.doc.lineAt(r.head).number, view.state.doc.lineAt(r.head)]));
  const changes = [...lines.values()].map(line => {
    const box = /^\s*[-*+] \[([ xX])\]/.exec(line.text);
    if (box) return { from: line.from + box[0].length - 2, to: line.from + box[0].length - 1, insert: box[1] === " " ? "x" : " " };
    const bullet = /^\s*[-*+] /.exec(line.text);
    return bullet ? { from: line.from + bullet[0].length, insert: "[ ] " } : { from: line.from + /^\s*/.exec(line.text)![0].length, insert: "- [ ] " };
  });
  view.dispatch({ changes });
  return true;
}

/** Buttons for what the keyboard does with lines, as phones have no Alt or Tab; they keep the editor's focus. */
function toolbar(view: EditorView): HTMLElement {
  const bar = Object.assign(document.createElement("div"), { className: "cm-tools" });
  const tools: [string, string, (view: EditorView) => boolean][] = [
    ["↑", "Move the line up (Alt+↑)", moveLineUp],
    ["↓", "Move the line down (Alt+↓)", moveLineDown],
    ["⇤", "Outdent (Shift+Tab)", indentLess],
    ["⇥", "Indent (Tab)", indentMore],
    ["☑", "Make the line a task, or tick it", task]
  ];
  for (const [label, title, run] of tools) {
    const button = Object.assign(document.createElement("button"), { type: "button", className: "quiet icon", textContent: label, title, ariaLabel: title });
    button.onpointerdown = event => event.preventDefault();
    button.onclick = () => run(view);
    bar.append(button);
  }
  return bar;
}

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
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap, indentWithTab]),
    markdown({ base: markdownLanguage }),
    linking,
    showPanel.of(view => ({ dom: toolbar(view), top: true })),
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
