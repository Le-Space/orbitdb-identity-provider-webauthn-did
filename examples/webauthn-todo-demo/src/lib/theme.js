import { writable } from "svelte/store";

// Create a writable store for the theme
function createThemeStore() {
  // Initialize theme based on system preference or localStorage
  const getInitialTheme = () => {
    const stored = localStorage.getItem("carbon-theme");
    if (stored) return stored;

    // Check system preference
    if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "g100"; // Carbon dark theme
    }

    return "white"; // Carbon light theme
  };

  const { subscribe, set, update } = writable(getInitialTheme());

  return {
    subscribe,
    set: (newTheme) => {
      localStorage.setItem("carbon-theme", newTheme);
      document.documentElement.setAttribute("theme", newTheme);
      document.documentElement.style.setProperty(
        "color-scheme",
        newTheme === "g100" ? "dark" : "light",
      );
      console.log("Theme set to:", newTheme);
      set(newTheme);
    },
    toggle: () => {
      let currentTheme;
      update((theme) => {
        currentTheme = theme === "white" ? "g100" : "white";
        localStorage.setItem("carbon-theme", currentTheme);
        document.documentElement.setAttribute("theme", currentTheme);
        document.documentElement.style.setProperty(
          "color-scheme",
          currentTheme === "g100" ? "dark" : "light",
        );
        console.log("Theme toggled to:", currentTheme);
        return currentTheme;
      });
    },
    init: () => {
      const initialTheme = getInitialTheme();
      console.log("Initializing theme:", initialTheme);

      // Apply theme to document
      document.documentElement.setAttribute("theme", initialTheme);
      document.documentElement.style.setProperty(
        "color-scheme",
        initialTheme === "g100" ? "dark" : "light",
      );

      // Update store
      set(initialTheme);

      // Listen for system theme changes if the user hasn't chosen a theme
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      mediaQuery.addEventListener("change", (e) => {
        if (!localStorage.getItem("carbon-theme")) {
          const newTheme = e.matches ? "g100" : "white";
          console.log("System theme changed to:", newTheme);
          document.documentElement.setAttribute("theme", newTheme);
          document.documentElement.style.setProperty(
            "color-scheme",
            newTheme === "g100" ? "dark" : "light",
          );
          set(newTheme);
        }
      });
    },
  };
}

export const theme = createThemeStore();
