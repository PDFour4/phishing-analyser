function startScan(event) {
    event.preventDefault(); // Prevent immediate form submission
    document.getElementById("loading").style.display = "block";

    let progressBar = document.getElementById("progress-bar");
    let scanText = document.getElementById("scan-text");
    let progress = 0;
    let messages = [
        "Extracting Headers...",
        "Scanning Links...",
        "Analyzing Attachments...",
        "Finalizing Results...",
        "Analysis Complete!"
    ];

    // Function to update the progress bar and scan text
    function updateProgress(duration) {
        return new Promise((resolve) => {
            const interval = duration / 100; // Calculate interval based on duration
            function step() {
                if (progress < 100) {
                    progress += 1; // Increase progress
                    progressBar.style.width = progress + "%";
                    progressBar.innerText = progress + "%";

                    let msgIndex = Math.floor(progress / 25); // Calculate message index based on progress
                    if (msgIndex < messages.length) {
                        scanText.innerText = messages[msgIndex]; // Update scan text
                    }

                    setTimeout(step, interval); // Adjust step timing based on duration
                }
                else {
                    resolve(); // Resolve the promise when progress is complete
                }
            }
            step();
        });
    }

    // Submit the form using fetch and wait for the server response
    const form = document.forms[0];
    const formData = new FormData(form);

    const startTime = Date.now(); // Record the start time
    const fetchPromise = fetch(form.action, {
        method: form.method,
        body: formData,
    })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            return response.text(); // Wait for the server response
        });

    // Wait for both the animation and the server response to complete
    fetchPromise
        .then(() => {
            const endTime = Date.now(); // Record the end time
            const responseDuration = endTime - startTime; // Calculate server response time
            const minimumDuration = 4000; // Set a minimum animation duration (e.g., 4 seconds)
            const duration = Math.max(responseDuration, minimumDuration); // Ensure the animation lasts at least the minimum duration
            return updateProgress(duration); // Synchronize animation with server response time
        })
        .then(() => {
            // Ensure the progress bar visually fills completely before transitioning
            setTimeout(() => {
                window.location.href = "/results"; // Redirect to results page
            }, 500); // Add a small delay to ensure the bar visually fills
        })
        .catch((error) => {
            console.error("There was a problem with the fetch operation:", error);
        });
}