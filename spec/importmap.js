const importMap = {
    imports: {
        "chai": "/base/node_modules/chai/chai.js",
        "chai-as-promised": "/base/node_modules/chai-as-promised/lib/chai-as-promised.js",
        "check-error": "/base/node_modules/check-error/index.js"
    },
};

const importmap = document.createElement("script");
importmap.type = "importmap";
importmap.textContent = JSON.stringify(importMap);
document.currentScript.after(importmap);