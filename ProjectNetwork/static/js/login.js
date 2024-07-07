document.addEventListener("DOMContentLoaded", function() {
    // User icon pop-up menu
    const userIcon = document.getElementById("userIcon");
    const popupMenu = document.getElementById("popupMenu");

    userIcon.addEventListener("click", function() {
        popupMenu.style.display = popupMenu.style.display === "block" ? "none" : "block";
    });

    // Close the popup if clicked outside
    document.addEventListener("click", function(event) {
        if (!userIcon.contains(event.target) && !popupMenu.contains(event.target)) {
            popupMenu.style.display = "none";
        }
    });
});