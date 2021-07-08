class Progress {
    constructor(status, progress_value_el, status_text_el, progress_change_func) {
        this.progress_value = progress_value_el;
        this.status_text = status_text_el;
        this.current_status = status;
        this.progress_change_func = progress_change_func || this.pcf;
        this.update(status);
    }

    pcf(percent) {
        return `${percent*100}%`
    }

    update(status) {
        for (let key of Object.keys(status)) {
            switch (key) {
                case "status":
                    let valid = true;
                    switch (status.status) {
                        case "error":
                            this.progress_value.style.background = "var(--red)";
                            this.progress_value.style.width = this.progress_change_func(1);
                            break;
                        case "success":
                            this.progress_value.style.background = "var(--green)";
                            this.progress_value.style.width = this.progress_change_func(1);
                            break;
                        case "neutral":
                            this.progress_value.style.background = "var(--bright)";
                            break;
                        default:
                            valid = false;
                    }
                    if (valid) this.current_status.status = status.status;
                    break;
                case "statusText":
                    this.current_status.statusText = status.statusText;
                    this.status_text.innerText = status.statusText;
                    break;
                case "progress":
                    this.current_status.progress = status.progress;
                    this.progress_value.style.width = this.progress_change_func(status.progress);
                    break;
            }
        }
    }
}
