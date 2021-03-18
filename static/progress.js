class Progress {
    constructor(status) {
        this.progress_value = document.getElementsByClassName('progress-value')[0];
        this.status_text = document.getElementById("status");
        this.current_status = status;
        this.update(status);
    }

    update(status) {
        for (let key of Object.keys(status)) {
            switch (key) {
                case "status":
                    let valid = true;
                    switch (status.status) {
                        case "error":
                            this.progress_value.style.background = "var(--red)";
                            this.progress_value.style.width = '100%';
                            break;
                        case "success":
                            this.progress_value.style.background = "var(--green)";
                            this.progress_value.style.width = '100%';
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
                    this.progress_value.style.width = status.progress*100+'%';
                    break;
            }
        }
    }
}
