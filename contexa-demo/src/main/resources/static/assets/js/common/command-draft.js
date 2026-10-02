export class CommandDraft {
    constructor(name, username) {
        this.key = `lab.command.${name}.${username}`;
        this.saved = JSON.parse(sessionStorage.getItem(this.key) || 'null');
    }

    clear() {
        sessionStorage.removeItem(this.key);
        this.saved = null;
    }

    input() {
        return this.saved?.input;
    }

    prepare(input) {
        if (this.saved && JSON.stringify(this.saved.input) === JSON.stringify(input)) {
            return { commandId: this.saved.commandId, ...input };
        }
        const next = { commandId: crypto.randomUUID(), input };
        sessionStorage.setItem(this.key, JSON.stringify(next));
        this.saved = next;
        return { commandId: next.commandId, ...input };
    }
}
