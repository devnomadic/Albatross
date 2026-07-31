// World map visualization for AbuseIPDB reputation results.
// Shows the reported abuser's origin country (highlighted red) and the
// countries of the reporters who filed abuse reports against it (shaded
// blue, darker = more reports), using the jsVectorMap library.
window.AlbatrossWorldMap = (function () {
    "use strict";

    let mapInstance = null;

    function hexOrRgb(rgbArray) {
        return "rgb(" + rgbArray[0] + ", " + rgbArray[1] + ", " + rgbArray[2] + ")";
    }

    function colorForCount(count, maxCount) {
        if (!count || maxCount <= 0) {
            return null;
        }
        const ratio = Math.min(count / maxCount, 1);
        const from = [173, 216, 255]; // light blue
        const to = [13, 71, 161]; // dark blue
        const rgb = from.map((c, i) => Math.round(c + (to[i] - c) * ratio));
        return hexOrRgb(rgb);
    }

    function destroy() {
        if (mapInstance) {
            try {
                mapInstance.destroy();
            } catch (e) {
                // ignore teardown errors
            }
            mapInstance = null;
        }
    }

    function render(containerId, originCode, originName, targets) {
        const container = document.getElementById(containerId);
        if (!container || typeof jsVectorMap === "undefined") {
            return;
        }

        destroy();
        container.innerHTML = "";

        targets = targets || [];
        const originUpper = (originCode || "").toUpperCase();
        const targetsByCode = {};
        let maxCount = 0;
        targets.forEach(function (t) {
            if (t && t.code) {
                const code = t.code.toUpperCase();
                targetsByCode[code] = t;
                if (t.count > maxCount) {
                    maxCount = t.count;
                }
            }
        });

        mapInstance = new jsVectorMap({
            selector: "#" + containerId,
            map: "world",
            zoomButtons: true,
            zoomOnScroll: false,
            backgroundColor: "transparent",
            regionStyle: {
                initial: { fill: "#3a3f4a", stroke: "#20242c", strokeWidth: 0.5 },
                hover: { fillOpacity: 0.85, cursor: "pointer" }
            },
            onRegionTooltipShow: function (event, tooltip, code) {
                const parts = [];
                if (code === originUpper) {
                    parts.push("Reported abuser origin" + (originName ? " (" + originName + ")" : ""));
                }
                const match = targetsByCode[code];
                if (match) {
                    parts.push(match.count + " report" + (match.count === 1 ? "" : "s") + " filed by reporters here");
                }
                if (parts.length) {
                    tooltip.text(tooltip.text() + " — " + parts.join(" · "), false);
                }
            },
            onLoaded: function (map) {
                Object.keys(targetsByCode).forEach(function (code) {
                    if (map.regions[code]) {
                        const color = colorForCount(targetsByCode[code].count, maxCount);
                        if (color) {
                            map.regions[code].element.setStyle("fill", color);
                        }
                    }
                });
                if (originUpper && map.regions[originUpper]) {
                    map.regions[originUpper].element.setStyle("fill", "#e53935");
                    map.regions[originUpper].element.setStyle("stroke", "#ffffff");
                    map.regions[originUpper].element.setStyle("strokeWidth", 1.5);
                }
            }
        });
    }

    return {
        render: render,
        destroy: destroy
    };
})();
