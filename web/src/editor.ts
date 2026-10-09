// A doc's editor: markdown in CodeMirror, bound to the doc's Yjs text, which edits here and the session's own copy
// (lmk-node's) keep in step. "- [ ]" items show as checkboxes that tick with
// a click; a toolbar (and Alt+↑/↓, Tab, Shift+Tab) moves and indents lines. Links show as their text, and open on a
// click, except on the line being edited. Images the doc links show below their line; pasting or dropping a file
// uploads it and inserts its link.
import { defaultKeymap, indentLess, indentMore, indentWithTab, moveLineDown, moveLineUp } from "@codemirror/commands";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting, syntaxTree } from "@codemirror/language";
import { EditorState, type Range, StateField } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate, WidgetType, keymap, placeholder, showPanel } from "@codemirror/view";
import { yCollab, yUndoManagerKeymap } from "y-codemirror.next";
import * as Y from "yjs";
import type { Session } from "./client";

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
 * image the doc links (`![alt](lmk:…)`) shows only as the image below its line, unless a cursor is on that line.
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

/** Links, which open on a click: web and mail links in a new tab, a file the doc links as a download. */
const linking = (blobs: Blobs) =>
  ViewPlugin.fromClass(
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
          const link = (event.target as HTMLElement).closest(".cm-link");
          const href = link?.getAttribute("data-href") ?? "";
          if (href.startsWith("lmk:")) blobs.open(href, link!.textContent!);
          else if (/^(https?|mailto):/i.test(href)) window.open(href, "_blank", "noopener");
          else return false;
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

/**
 * How the editor reaches the files the doc links: a linked image as a data: URL, uploading a file (which gives its
 * link), and saving a linked file.
 */
export type Blobs = {
  show: (link: string) => Promise<string>;
  attach: (bytes: Uint8Array) => Promise<string>;
  open: (link: string, name: string) => void;
  fail: (error: unknown) => void;
};

const LONGEST_SIDE = 1600;

class Picture extends WidgetType {
  constructor(
    readonly link: string,
    readonly blobs: Blobs
  ) {
    super();
  }

  eq(other: Picture) {
    return other.link === this.link;
  }

  toDOM(view: EditorView) {
    const box = Object.assign(document.createElement("div"), { className: "cm-image" });
    box.style.padding = "4px 0";
    this.blobs.show(this.link).then(
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

function pictures(state: EditorState, blobs: Blobs): DecorationSet {
  const found: Range<Decoration>[] = [];
  for (const match of state.doc.toString().matchAll(/!\[[^\]\n]*\]\((lmk:[0-9a-f]{64}\.[0-9]+#[0-9a-f]{64})\)/g)) {
    const end = state.doc.lineAt(match.index).to;
    found.push(Decoration.widget({ widget: new Picture(match[1], blobs), block: true, side: 1 }).range(end));
  }
  return Decoration.set(found, true);
}

/** An image scaled to at most LONGEST_SIDE pixels, as WebP (JPEG where the browser cannot). */
async function shrink(file: Blob): Promise<Uint8Array> {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, LONGEST_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = new OffscreenCanvas(Math.max(1, Math.round(bitmap.width * scale)), Math.max(1, Math.round(bitmap.height * scale)));
  canvas.getContext("2d")!.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  let encoded = await canvas.convertToBlob({ type: "image/webp", quality: 0.9 });
  if (encoded.type !== "image/webp") encoded = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.9 });
  return new Uint8Array(await encoded.arrayBuffer());
}

/**
 * Uploads `files` (images scaled down) and inserts their links on lines of their own, after the line at `at`, so that
 * a drop never splits a link; false if there are none, so the editor handles the event.
 */
function insertFiles(view: EditorView, blobs: Blobs, event: Event, files: FileList | undefined, at: number): boolean {
  if (!files?.length) return false;
  event.preventDefault();
  for (const file of files) {
    const image = /^image\/(png|jpeg|gif|webp)$/.test(file.type);
    const name = (image ? file.name.replace(/\.[^.]*$/, "") : file.name).replace(/[[\]]/g, "");
    (image ? shrink(file) : file.arrayBuffer().then(bytes => new Uint8Array(bytes)))
      .then(blobs.attach)
      .then(link => {
        const line = view.state.doc.lineAt(Math.min(at, view.state.doc.length));
        view.dispatch({ changes: { from: line.to, insert: `${line.length ? "\n" : ""}${image ? "!" : ""}[${name}](${link})` } });
      })
      .catch(blobs.fail);
  }
  return true;
}

/** From the session: an edit made elsewhere. */
const REMOTE = "lmk";

/** An editor of the doc `gid`. `edited` takes in what the session's copy has that this one lacks. */
export async function bind(parent: HTMLElement, lmk: Session, gid: string, blobs: Blobs) {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, await lmk.doc(gid), REMOTE);
  doc.on("update", (update: Uint8Array, origin: unknown) => origin !== REMOTE && lmk.edit(gid, update).catch(blobs.fail));
  const view = editor(parent, doc.getText("text"), blobs);
  return {
    edited: () => lmk.doc_diff(gid, Y.encodeStateVector(doc)).then(diff => Y.applyUpdate(doc, diff, REMOTE), blobs.fail),
    measure: () => view.requestMeasure(),
    destroy: () => (view.destroy(), doc.destroy())
  };
}

function editor(parent: HTMLElement, text: Y.Text, blobs: Blobs): EditorView {
  const extensions = [
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap, indentWithTab]),
    markdown({ base: markdownLanguage }),
    linking(blobs),
    showPanel.of(view => ({ dom: toolbar(view), top: true })),
    syntaxHighlighting(defaultHighlightStyle),
    EditorView.lineWrapping,
    placeholder("Write here. Everyone in this document, people and agents, edits it at once."),
    checkboxes,
    StateField.define<DecorationSet>({
      create: state => pictures(state, blobs),
      update: (decorations, tr) => (tr.docChanged ? pictures(tr.state, blobs) : decorations),
      provide: field => EditorView.decorations.from(field)
    }),
    EditorView.domEventHandlers({
      paste: (event, view) => insertFiles(view, blobs, event, event.clipboardData?.files, view.state.selection.main.head),
      drop: (event, view) => insertFiles(view, blobs, event, event.dataTransfer?.files, view.posAtCoords(event) ?? view.state.selection.main.head)
    }),
    yCollab(text, null)
  ];
  return new EditorView({ parent, state: EditorState.create({ doc: text.toString(), extensions }) });
}
