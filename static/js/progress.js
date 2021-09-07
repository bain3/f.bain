class Progress {
    colors = {"error": "--error", "success": "--success", "neutral": "--white"}

    constructor(status, progress_value_el, status_text_el, progress_change_func) {
        this.progress_value = progress_value_el;
        this.status_text = status_text_el;
        this.progress_change_func = progress_change_func || this.pcf;
        this.update(status);
    }

    pcf(percent) {
        return `${percent*100}%`
    }

    update(status) {
        if (status === undefined) return;
        if (status.progress !== undefined) {
            this.progress_value.style.width = this.progress_change_func(status.progress);
        }
        if (status.statusText !== undefined) {
            this.status_text.innerText = status.statusText;
        }
        if (status.status !== undefined) {
            if (status.status !== "neutral") this.progress_value.style.width = this.progress_change_func(1);
            this.progress_value.style.background = `var(${this.colors[status.status]})`;
        }
    }
}
