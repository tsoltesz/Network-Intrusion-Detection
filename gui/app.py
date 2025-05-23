import threading, queue, datetime, time, sys
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import List
import joblib
import xgboost as xgb
import pandas as pd
import datetime
import csv
from winotify import Notification, audio
import lightgbm as lgb
from catboost import CatBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingClassifier

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

try:
    import pystray
except ImportError:
    pystray = None

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    sniff = None

DEFAULT_THEME    = "light"
DEFAULT_LANGUAGE = "en"

THEMES = {
    "light": {
        "bg": "#FFFFFF",
        "bg2": "#F6F6F6",
        "fg": "#000000",
        "accent": "#0078D7",
        "start_green": "#28A745",
        "stop_red": "#DC3545",
        "table_row_alt": "#EBEBEB",
        "sel_bg": "#D0E7FF",
        "sel_fg": "#000000",
        "btn_sel": "#E2E2E2",
        "warning": "#FFCCCC",
        "normal_button": "#D0E7FF",
    },
    "dark": {
        "bg": "#202124",
        "bg2": "#2A2C2F",
        "fg": "#E8EAED",
        "accent": "#0A84FF",
        "start_green": "#34C759",
        "stop_red": "#FF453A",
        "table_row_alt": "#303134",
        "sel_bg": "#1E4F8F",
        "sel_fg": "#E8EAED",
        "btn_sel": "#3A3B3D",
        "warning": "#FF0000",
        "normal_button": "#1E4F8F",
    },
}

TRANSLATIONS = {

    "hu": {
        "time":"Időbélyeg",
        "src": "Forrás IP",
        "dst": "Cél IP",
        "proto": "Protokoll",
        "flow_dur": "Időtartam",
        "pps": "CSMG/S",
        "bwd_data_pkts_tot":"össz_v_adat_csmg",
        "fwd_pkts_tot":"össz_e_csmg",
        "fwd_header_size_tot": "össz_e_fejlec_meret",
        "app_name": "FelineGuard",
        "settings": "Beállítások",
        "run_bg": "Futtatás a háttérben",
        "start": "Start",
        "stop": "Stop",
        "theme": "Téma",
        "language": "Nyelv",
        "model": "Modell",
        "save": "Beállítások mentése",
        "status_ready": "Kész.",
        "status_running": "Fut...",
        "status_attack": "Lehetséges támadás: ",
        "scapy_message": "A Scapy nincs telepítve!",
        "pystray_message": "A pystray csomag nem található!",
        "quit_message": "A sniffelés még fut. Biztos kilépsz?",
        "yes": "Igen",
        "no":  "Nem",
        "help": "Súgó",
        "help_text": "Ez az alkalmazás valós időben figyeli a hálózati forgalmat, és jelzi, ha az adott gépet támadás éri. A megfigyelést a START gombbal indíthatod el, majd egy táblázatban követheted nyomon a bejövő és kimenő csomagokat. Gyanús vagy hibás csomag esetén a sor piros színnel emelkedik ki, az állapotsor pedig megjeleníti az utolsó észlelt támadás időpontját. A figyelés leállításához nyomd meg a STOP gombot.\n A Beállítások menüben kiválaszthatod a megjelenési témát és a program nyelvét, továbbá azt is, hogy melyik gépi tanulási modell alapján történjen a támadások osztályozása. A rendszer emellett minden forgalmi adatot és a hozzájuk tartozó támadási címkéket egy naplófájlba is elmenti.",
        "quit":"Kilépés",
        "display": "Megjelenítés",
        "t_light": "Világos",
        "t_dark": "Sötét",
    },
    "en": {
        "time":"Timestamp",
        "src": "Source IP",
        "dst": "Destination IP",
        "proto": "Protocol",
        "flow_dur": "Duration",
        "pps": "PKTS/S",
        "bwd_data_pkts_tot":"Bwd_data_pkts_tot",
        "fwd_pkts_tot":"FWD_PKTS_TOT",
        "fwd_header_size_tot": "FWD_HEADER_SIZE_TOT",
        "app_name": "FelineGuard",
        "settings": "Settings",
        "run_bg": "Run in background",
        "start": "Start",
        "stop": "Stop",
        "theme": "Theme",
        "language": "Language",
        "model": "Model",
        "save": "Save settings",
        "status_ready": "Ready.",
        "status_running": "Running...",
        "status_attack": "Possible attack: ",
        "time":"Time",
        "scapy_message": "Scapy not installed",
        "pystray_message": "Pystray not installed",
        "quit_message": "Sniff is running. Do you quit?",
        "yes": "Yes",
        "no":  "No",
        "help": "Help",
        "help_text": "This application monitors network traffic in real time and notifies you if your machine is under attack. Monitoring begins when you press the START button, and you can then track incoming and outgoing packets in a table. Suspicious or malformed packets are highlighted in red, and the status bar displays the time of the last detected attack. To stop monitoring, press the STOP button.\nIn the Settings menu, you can choose the display theme and program language, as well as which machine learning model will be used for attack classification. The system also saves all traffic data and their associated attack labels to a log file.",
        "quit":"Quit",
        "display": "Display",
        "t_light": "Light",
        "t_dark": "Dark",
    },
    "de": {
        "time": "Zeitstempel",                    
        "src": "Quell IP",                       
        "dst": "Ziel IP",                         
        "proto": "Protokoll",                    
        "flow_dur": "Dauer",                     
        "pps": "Pakete/Sek",                     
        "bwd_data_pkts_tot": "GR_Daten_pkt",   
        "fwd_pkts_tot": "GV_Pkt",             
        "fwd_header_size_tot": "V_Header_Größe" ,
        "app_name": "FelineGuard",
        "settings": "Einstellungen",
        "run_bg": "Im Hintergrund ausführen",
        "start": "Start",
        "stop": "Stopp",
        "theme": "Thema",
        "language": "Sprache",
        "model": "Modell",
        "save": "Einstellungen speichern",
        "status_ready": "Bereit.",
        "status_running": "Läuft...",
        "status_attack": "Möglicher Angriff: ",
        "scapy_message": "Scapy nicht installiert",
        "pystray_message": "Pystray nicht installiert",
        "quit_message": "Der Sniff läuft. Möchten Sie beenden?",
        "yes": "Ja",
        "no":  "Nein",
        "help": "Helfen",
        "help_text": "Diese Anwendung überwacht den Netzwerkverkehr in Echtzeit und informiert Sie, wenn Ihr Computer angegriffen wird. Die Überwachung beginnt, wenn Sie die START-Schaltfläche drücken, und Sie können eingehende und ausgehende Pakete in einer Tabelle verfolgen. Verdächtige oder fehlerhafte Pakete werden rot hervorgehoben, und die Statusleiste zeigt den Zeitpunkt des zuletzt erkannten Angriffs an. Um die Überwachung zu beenden, drücken Sie die STOP-Schaltfläche.\nIm Einstellungsmenü können Sie das Anzeige‑Thema und die Programmsprache auswählen sowie festlegen, welches Machine‑Learning‑Modell für die Angriffserkennung verwendet werden soll. Das System speichert außerdem alle Verkehrsdaten und deren zugehörige Angriffskennzeichnungen in einer Protokolldatei.",
        "quit":"Aufhören",
        "display": "Anzeige",
        "t_light": "Licht",
        "t_dark": "Dunkel",
       
    },
}

ICON_DIR = Path("img")
GEAR_ICON_LIGHT  = ICON_DIR / "gear_light.png"
HELP_ICON_LIGHT  = ICON_DIR / "help_logo_light.png"
GEAR_ICON_DARK  = ICON_DIR / "gear_dark.png"
HELP_ICON_DARK  = ICON_DIR / "help_logo_dark.png"
PLAY_ICON  = ICON_DIR / "play.png"
STOP_ICON  = ICON_DIR / "stop.png"
APP_ICON   = ICON_DIR / "logo.png"
TRAY_ICON  = ICON_DIR / "logo.ico"
LOGO_ICON_ICO = ICON_DIR / "logo.ico"
FLAG_ICONS = {c: ICON_DIR / f"{c}.png" for c in ("hu", "en", "de")}

def load_img(path: Path, size):
    if Image and path.exists():
        return ImageTk.PhotoImage(Image.open(path).resize(size, Image.LANCZOS))
    return None

class FlowStat:
    __slots__ = (
        "initiator", "t0", "t_last",
        "tot_pkts", "fwd_pkts",
        "bwd_data_pkts_tot", "fwd_header_size_tot",
    )

    def __init__(self, initiator, t0):
        self.initiator = initiator
        self.t0 = t0
        self.t_last = t0
        self.tot_pkts = 0
        self.fwd_pkts = 0
        self.bwd_data_pkts_tot = 0
        self.fwd_header_size_tot = 0

    def update(self, pkt, ts):
        self.t_last = ts
        self.tot_pkts += 1
        if pkt[IP].src == self.initiator:
            self.fwd_pkts += 1
            self.fwd_header_size_tot += len(pkt)
        else:
            if len(pkt.payload) > 0:
                self.bwd_data_pkts_tot += 1

    def duration_sec(self):
        return max((self.t_last - self.t0).total_seconds(), 1e-6)

class Sniffer(threading.Thread):
    def __init__(self, stop_event, q):
        super().__init__(daemon=True)
        self.stop_event = stop_event
        self.q = q
        self.flows = {}

    def _key(self, pkt, proto):
        return (pkt[IP].src, pkt[IP].dst, proto)

    def _enqueue_packet(self, pkt):
        if self.stop_event.is_set():
            raise KeyboardInterrupt

        ts = datetime.datetime.now()
        timestr = ts.strftime("%Y-%m-%d %H:%M:%S")
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else pkt.lastlayer().name
        key = self._key(pkt, proto)

        if key not in self.flows:
            self.flows[key] = FlowStat(pkt[IP].src, ts)

        flow = self.flows[key]
        flow.update(pkt, ts)
        dur = flow.duration_sec()
        pps = flow.tot_pkts / dur

        self.q.put((
            timestr,
            pkt[IP].src,
            pkt[IP].dst,
            proto,
            f"{dur:.3f}",
            f"{pps:.2f}",
            flow.bwd_data_pkts_tot,
            flow.fwd_pkts,
            flow.fwd_header_size_tot
        ))



    def run(self):
        if sniff is None:
            self.q.put(("ERR", "Scapy not installed", "", ""))
            return
        try:
            sniff(lfilter=lambda p: p.haslayer(IP), prn=self._enqueue_packet, store=0, stop_filter=lambda _: self.stop_event.is_set())
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.q.put(("ERR", str(e), "", ""))

class ToggleButton(ttk.Frame):
    def __init__(self, master, translate, **kw):
        super().__init__(master, **kw)
        self._          = translate
        self.is_running = False
        self.play       = load_img(PLAY_ICON, (30, 30))
        self.stop       = load_img(STOP_ICON, (30, 30))
        self.btn        = ttk.Button(self, command=self.toggle)
        self.btn.pack(fill="both", expand=True)
        self._update()

    def _update(self):
        txt, img, st = (
            (self._("stop"),  self.stop,  "Stop.TButton")
            if self.is_running else
            (self._("start"), self.play,  "Start.TButton")
        )
        self.btn.configure(text=txt, image=img, compound="left", style=st)

    def toggle(self):
        self.is_running = not self.is_running
        self._update()
        self.event_generate("<<Toggle>>", when="tail")

class InspectorApp:
    MODEL_DIR = 'models'

    def __init__(self):

        self.SNIFFER_LOG_FILE = "logs\\"+self.get_timestamped_filename()

        with open(self.SNIFFER_LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            columns = (
                "time", "src", "dst", "proto",
                "flow_dur", "pps",
                "bwd_data_pkts_tot",
                "fwd_pkts_tot",
                "fwd_header_size_tot",
                "predicted_label"
            )
            writer.writerow(columns)

        self.MODELS = self.list_files(self.MODEL_DIR)
        self.MODEL_FILE = self.MODELS[0]
        self.handle_model(self.MODEL_FILE)

        self.auto_scroll_enabled = True

        self.root = tk.Tk()
        self.root.minsize(width=900, height=600)
        self.root.iconbitmap(LOGO_ICON_ICO)

        self._q          = queue.Queue()
        self._stop_event = threading.Event()
        self._sniffer    = None

        self.theme, self.language = DEFAULT_THEME, DEFAULT_LANGUAGE
        self.style = ttk.Style(self.root)
        self.style.theme_use("default")
        self.style.configure(
            "ActiveLang.TButton",
            relief="flat",
            borderwidth=0,
            font=("Segoe UI", 10, "bold"),
        )

        self._conf_styles()
        self._build_ui()
        self._apply_theme()
        self._translate_ui()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_queue)

        self.is_hidden = False

    def _(self, k): return TRANSLATIONS[self.language][k]

    def _translate_ui(self):
        self.name_lbl.config(text=self._("app_name"))
        self.bg_btn.config(text=self._("run_bg"))
        self.root.title(self._("app_name"))
        self.toggle_btn._update()
        self._set_status(
            self._("status_running") if self.toggle_btn.is_running else self._("status_ready")
        )

        columns  = (
            "time", "src", "dst", "proto",
            "flow_dur", "pps",
            "bwd_data_pkts_tot",
            "fwd_pkts_tot",
            "fwd_header_size_tot",
        )

        headings = {
            "time": self._("time").upper(),
            "src": self._("src").upper(),
            "dst": self._("dst").upper(),
            "proto": self._("proto").upper(),
            "flow_dur": self._("flow_dur").upper(),
            "pps": self._("pps").upper(),
            "bwd_data_pkts_tot": self._("bwd_data_pkts_tot").upper(),
            "fwd_pkts_tot":   self._("fwd_pkts_tot").upper(),
            "fwd_header_size_tot": self._("fwd_header_size_tot").upper(),
        }
        widths = {
            "time":140, "src":110, "dst":110, "proto":70,
            "flow_dur":90, "pps":80,
            "bwd_data_pkts_tot":120,
            "fwd_pkts_tot":100,
            "fwd_header_size_tot":130,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, anchor="center", minwidth=widths[col], stretch=True)

        

    def _set_status(self, t=None):
        self.status_lbl.config(text=t or self._("status_ready"))

    def _conf_styles(self):
        base = ("Segoe UI", 10)
        for s in ("TLabel", "TButton", "TRadiobutton", "TCombobox"):
            self.style.configure(s, padding=2, font=base)
        self.style.configure("Start.TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Stop.TButton",  font=("Segoe UI", 10, "bold"))
        self.style.configure("Tool.TButton",  relief="flat", borderwidth=0)
        self.style.configure("BgBtn.TButton", font=("Segoe UI", 10, "bold"))
        


    def _apply_theme(self):
        t = THEMES[self.theme]
        self.root.configure(bg=t["bg"])

        for e in ("TFrame", "TLabelframe", "TLabel", "TRadiobutton",
                  "TCombobox", "TButton"):
            self.style.configure(e, background=t["bg"], foreground=t["fg"])

        self.style.configure("Treeview", background=t["bg2"],
                             fieldbackground=t["bg2"], foreground=t["fg"],
                             bordercolor=t["bg2"])
        self.style.configure("Treeview.Heading", background=t["accent"],
                             foreground=t["bg"], relief="flat")
        self.style.map("Treeview",
                       background=[("selected", t["sel_bg"])],
                       foreground=[("selected", t["sel_fg"])])

        self.style.map("TCombobox",
                       fieldbackground=[("readonly", t["bg2"])],
                       selectbackground=[("readonly", t["sel_bg"])],
                       selectforeground=[("readonly", t["sel_fg"])])

        self.style.map("Start.TButton",
                       background=[("!active", t["start_green"]),
                                   ("active",  t["accent"])],
                       foreground=[("!active", t["bg"]),
                                   ("active",  t["bg"])])
        self.style.map("Stop.TButton",
                       background=[("!active", t["stop_red"]),
                                   ("active",  t["accent"])],
                       foreground=[("!active", t["bg"]),
                                   ("active",  t["bg"])])

        self.style.configure("Status.TFrame", background=t["bg2"])
        self.status_lbl.configure(background=t["bg2"], foreground=t["fg"])

        self.style.map("Tool.TButton",
                       background=[("pressed", t["btn_sel"]),
                                   ("active",  t["btn_sel"])])
        self.style.map("ActiveLang.TButton",
                       background=[("pressed", t["btn_sel"]),
                                   ("active",  t["btn_sel"])])

        self.style.map("Normal.TButton",
                       background=[("pressed", t["normal_button"]),
                                   ("active",  t["normal_button"])])

        self.style.map("BgBtn.TButton",
                       background=[("pressed", t["normal_button"]),
                                   ("active",  t["normal_button"])])


        self.tree.tag_configure("attack", background=t['warning'])  
        self.tree.tag_configure("normal", background="")         # normál (nincs szín)

        if self.theme == "light":
            self.gear_icon = load_img(GEAR_ICON_LIGHT, (40, 40))
            self.help_icon = load_img(HELP_ICON_LIGHT, (40, 40))
            self.gear_btn.configure(image=self.gear_icon)
            self.help_btn.configure(image=self.help_icon)

        elif self.theme == "dark":
            self.gear_icon = load_img(GEAR_ICON_DARK, (40, 40))
            self.help_icon = load_img(HELP_ICON_DARK, (40, 40))
            self.gear_btn.configure(image=self.gear_icon)
            self.help_btn.configure(image=self.help_icon)

    def _build_ui(self):
        top = ttk.Frame(self.root); top.pack(fill="x")
        left = ttk.Frame(top); left.pack(side="left", padx=10, pady=5)

        logo = load_img(APP_ICON, (80, 80))
        if logo:
            ttk.Label(left, image=logo).pack(side="left")
            self._logo_img = logo  

        self.name_lbl = ttk.Label(left, font=("Impact", 20))
        self.name_lbl.pack(side="left", padx=6)

        self.gear_icon = load_img(GEAR_ICON_LIGHT, (40, 40))
        self.help_icon = load_img(HELP_ICON_LIGHT, (40, 40))

        self.gear_btn = ttk.Button(top,image=self.gear_icon,command=self._open_settings,style="Tool.TButton",)
        self.gear_btn.pack(side="right", padx=10, pady=5)

        self.help_btn = ttk.Button(top,image=self.help_icon,command=self._open_help,style="Tool.TButton",)
        self.help_btn.pack(side="right", padx=(10), pady=5)


        columns  = (
            "time", "src", "dst", "proto",
            "flow_dur", "pps",
            "bwd_data_pkts_tot",
            "fwd_pkts_tot",
            "fwd_header_size_tot",
        )
        tbl = ttk.Frame(self.root); tbl.pack(fill="both", expand=True,
                                             padx=10, pady=(0, 10))
        self.tree = ttk.Treeview(tbl, columns=columns, show="headings", height=14)

        headings = {
            "time": self._("time").upper(),
            "src": self._("src").upper(),
            "dst": self._("dst").upper(),
            "proto": self._("proto").upper(),
            "flow_dur": self._("flow_dur").upper(),
            "pps": self._("pps").upper(),
            "bwd_data_pkts_tot": self._("bwd_data_pkts_tot").upper(),
            "fwd_pkts_tot":   self._("fwd_pkts_tot").upper(),
            "fwd_header_size_tot": self._("fwd_header_size_tot").upper(),
        }
        widths = {
            "time":140, "src":110, "dst":110, "proto":70,
            "flow_dur":90, "pps":80,
            "bwd_data_pkts_tot":120,
            "fwd_pkts_tot":100,
            "fwd_header_size_tot":130,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, anchor="center", width=widths[col], stretch=True)

        self.tree.pack(side="left", fill="both", expand=True)
        self.vsb = ttk.Scrollbar(tbl, orient="vertical", command=self.tree.yview)
        
        self.tree.configure(yscrollcommand=self._on_tree_scroll)
        self.vsb.pack(side="right", fill="y")

        
        bottom = ttk.Frame(self.root); bottom.pack(fill="x", padx=10)
        self.toggle_btn = ToggleButton(bottom, self._)
        self.toggle_btn.pack(side="left", pady=10)
        self.toggle_btn.bind("<<Toggle>>", self._handle_toggle)

        self.bg_btn = ttk.Button(bottom, command=self._minimize_to_tray, style="BgBtn.TButton")
        self.bg_btn.pack(side="left", padx=10, ipady=8)

        status = ttk.Frame(self.root, style="Status.TFrame"); status.pack(fill="x")
        self.status_lbl = ttk.Label(status)
        self.status_lbl.pack(side="left", padx=8, pady=2)

        self._set_status()

        self.tree.tag_configure("attack", background=THEMES[self.theme]['warning'])  
        self.tree.tag_configure("normal", background="")         

    def _on_tree_scroll(self, first, last):
        
        self.vsb.set(first, last)
        
        try:
            self.auto_scroll_enabled = float(last) >= 0.9
        except ValueError:
            pass

    def _handle_toggle(self, *_):
        if self.toggle_btn.is_running:
            self._start_sniff()
        else:
            self._stop_sniff()

    def _start_sniff(self):
        if sniff is None:
            messagebox.showerror("Scapy", self._("scapy_message"))
            if self.toggle_btn.is_running:
                self.toggle_btn.toggle()
            return
        if self._sniffer and self._sniffer.is_alive():
            return
        self._stop_event.clear()
        self._sniffer = Sniffer(self._stop_event, self._q)
        self._sniffer.start()
        self._set_status(self._("status_running"))

    def _stop_sniff(self):
        self._stop_event.set()
        if self._sniffer:
            self._sniffer.join(timeout=1)
        self._sniffer = None
        self._set_status(self._("status_ready"))

    
    def _process_queue(self):    
        try:
        
            last_id = None
            while True:
                rec = self._q.get_nowait()
                if rec[0] == "ERR":
                    messagebox.showerror("Sniffer", rec[1])
                else:
                    try:
                        
                        features = [float(x) for x in rec[4:9]]
                        df = pd.DataFrame([features], columns=[
                            "flow_duration",
                            "flow_pkts_per_sec",
                            "bwd_data_pkts_tot",
                            "fwd_pkts_tot",
                            "fwd_header_size_tot"
                        ])
                        prediction = self.MODEL.predict(df)
                        tag = "attack" if int(prediction[0]) == 0 else "normal"
                    except Exception as e:
                        print("Predikciós hiba:", e)
                        tag = "normal" 

                    last_id = self.tree.insert("", "end", values=rec, tags=(tag,))
                    if self.auto_scroll_enabled:
                        self.tree.see(last_id)
                        
                    if int(prediction[0]) == 0:
                        self._set_status(
                            self._("status_attack")+rec[0]
                        )
        
                    with open(self.SNIFFER_LOG_FILE, "a", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        row = list(rec)  
                        row.append("attack" if int(prediction[0]) == 0 else "normal")
                        writer.writerow(row)

                    if int(prediction[0]) == 0 and self.is_hidden:
                        
                        toast = Notification(
                            app_id=self._("app_name"),                     
                            title=self._("status_attack"),               
                            msg=f"{rec[0]}: {rec[1]} → {rec[2]}",
                            icon=str((LOGO_ICON_ICO).resolve()) 
                
                        )
                        
                        toast.set_audio(audio.Default, loop=False)
                        toast.show()
                        self.is_hidden=False
                    
        except queue.Empty:
            pass
        finally:
            
            self.root.after(100, self._process_queue)


    def _restore_window(self):
        
        if hasattr(self, 'tray'):
            self.tray.stop()
        self.root.deiconify()
        self.is_hidden = False

    def _quit_from_tray(self):
    
        if hasattr(self, 'tray'):
            self.tray.stop()
        self._on_close()



    def _minimize_to_tray(self):
        if not pystray:
            messagebox.showwarning("Pystray", self._("pystray_message"))
            return
        self.root.withdraw()
        self.is_hidden = True
        ico = Image.open(TRAY_ICON) if Image and TRAY_ICON.exists() else None

        def _on_left_click(icon, item):
            
            icon.stop()
            self.root.after(0, self._restore_window)

        self.tray = pystray.Icon(
            self._("app_name"), ico, self._("app_name"),
            menu=pystray.Menu(
                pystray.MenuItem(
                    self._("display"),
                    lambda *_: self.root.after(0, self._restore_window),
                ),
                pystray.MenuItem(
                    self._("help"),
                    lambda *_: self.root.after(0, self._open_help),
                ),
                pystray.MenuItem(
                    self._("settings"),
                    
                    lambda *_: self.root.after(0, self._open_settings),
                ),
                pystray.MenuItem(
                    self._("quit"),
                    
                    lambda *_: self.root.after(0, self._quit_from_tray),
                ),
            ),
        )
        threading.Thread(target=self.tray.run, daemon=True).start()

    def _on_close(self):
        self._restore_window()
        if self.toggle_btn.is_running:
            
            title   = self._('app_name')
            message = self._('quit_message')
            if not self.ask_yes_no(title, message):
                return
        self._stop_sniff()
        self.root.destroy()

    def _open_settings(self):
        SettingsWindow(self)


    def handle_model(self, model_name: str):
        self.MODEL_FILE = model_name
        extension = model_name.split('.')
        if extension[-1].lower() == 'joblib':
            self.MODEL = joblib.load(Path(self.MODEL_DIR) / model_name)
        elif extension[-1].lower() == 'txt':
            self.MODEL = lgb.Booster(model_file=Path(self.MODEL_DIR) / model_name)
        elif extension[-1].lower() == 'cbm':
            self.MODEL = CatBoostClassifier()
            self.MODEL.load_model(Path(self.MODEL_DIR) / model_name)
        elif extension[-1].lower() == 'json':
            self.MODEL = xgb.XGBClassifier()
            self.MODEL.load_model(Path(self.MODEL_DIR) / model_name)
        else:
            print("NO SUPPORTED MODEL")


    def run(self):
        self.root.mainloop()

    def list_files(self, dir_path: str | Path) -> List[str]:
        
        p = Path(dir_path)
        return [child.name for child in p.iterdir() if child.is_file()]

    def get_timestamped_filename(self):
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"log_{timestamp}.csv"
        return filename


    def ask_yes_no(self, title: str, message: str) -> bool:
        
        t = THEMES[self.theme]
        resp = {"value": None}
        dlg = tk.Toplevel(self.root)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.title(title)
        ttk.Label(dlg, text=message, wraplength=300).pack(padx=20, pady=15)

        dlg.configure(bg=t["bg"])
        
        


        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=(0,15))

    
        yes_txt = self._("yes")
        no_txt  = self._("no")

        def on_yes():
            resp["value"] = True
            dlg.destroy()
        def on_no():
            resp["value"] = False
            dlg.destroy()

        ttk.Button(btn_frame, text=yes_txt, command=on_yes).pack(side="left", padx=5)
        ttk.Button(btn_frame, text=no_txt,  command=on_no).pack(side="left", padx=5)

    
        dlg.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dlg.winfo_height()) // 2
        dlg.geometry(f"+{x}+{y}")

        self.root.wait_window(dlg)
        return bool(resp["value"])

    def _open_help(self):
        HelpWindow(self, self._("help_text"))

    

class HelpWindow(tk.Toplevel):
    def __init__(self, app, help_text: str):
        super().__init__(app.root)
        self.app = app
        self.transient(app.root)
        self.resizable(False, False)
        self.iconbitmap(LOGO_ICON_ICO)


        t = THEMES[self.app.theme]
        self.configure(bg=t["bg"])
        

        
        self.title(f"{self.app._('app_name')} – {self.app._('help')}")

        
        frm = ttk.Frame(self, style="TFrame")
        frm.pack(padx=20, pady=20, fill="both", expand=True)

        
        if self.app.theme == "dark":
            icon_path = HELP_ICON_DARK
        elif self.app.theme == "light":
            icon_path = HELP_ICON_LIGHT
        
        img = load_img(icon_path, (80, 100))
        if img:
            lbl_icon = ttk.Label(frm, image=img, background=t["bg"])
            lbl_icon.image = img
            lbl_icon.pack(side="left", padx=(0,10))

        
        lbl = ttk.Label(
            frm,
            text=help_text,
            wraplength=300,
            background=t["bg"],
            foreground=t["fg"],
            font=("Segoe UI", 10)
        )
        lbl.pack(side="left", fill="both", expand=True)

    
        self.update_idletasks()  
    
        px = self.app.root.winfo_rootx()
        py = self.app.root.winfo_rooty()
        pw = self.app.root.winfo_width()
        ph = self.app.root.winfo_height()
        ww = self.winfo_width()
        wh = self.winfo_height()
        x = px + (pw - ww) // 2
        y = py + (ph - wh) // 2
        self.geometry(f"+{x}+{y}")
        
        self.grab_set()

   
class SettingsWindow(tk.Toplevel):
    def __init__(self, app: InspectorApp):
        super().__init__(app.root)
        
        self.app = app
        self.transient(app.root)
        self.resizable(False, False)

        self.theme_var = tk.StringVar(value=app.theme)
        self.lang_var  = tk.StringVar(value=app.language)
        self.model_var = tk.StringVar(value=app.MODEL_FILE)

        self.theme_var.trace_add("write", self._instant_theme)
        self.lang_var.trace_add("write",  self._instant_lang)

        self._build_widgets()
        self._sync_theme()
        self._sync_lang()
        self.grab_set()

    def _build_widgets(self):
        self.iconbitmap(LOGO_ICON_ICO)
    
        self.label_theme = ttk.Label(self)
        self.label_theme.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        tf = ttk.Frame(self); tf.grid(row=1, column=0, sticky="w", padx=10)

        self.theme_buttons = {}
        for key, txt in (("light", self.app._('t_light')), ("dark", self.app._('t_dark'))):
            rb = ttk.Radiobutton(tf, text=txt, variable=self.theme_var, value=key, style="ActiveLang.TButton" if self.theme_var.get()==key else "Tool.TButton")
            rb.pack(side="left", padx=4)
            self.theme_buttons[key] = rb

    
        self.label_lang = ttk.Label(self)
        self.label_lang.grid(row=2, column=0, sticky="w", padx=10, pady=(10, 0))
        lf = ttk.Frame(self); lf.grid(row=3, column=0, sticky="w", padx=10)
        self.lang_buttons = {}
        for code in ("hu", "en", "de"):
            img = load_img(FLAG_ICONS[code], (24, 16))
            btn = ttk.Button(lf, image=img, text=code.upper(),
                             compound="top", style="Tool.TButton",
                             command=lambda c=code: self.lang_var.set(c))
            btn.image = img
            btn.pack(side="left", padx=4)
            self.lang_buttons[code] = btn


        self.label_model = ttk.Label(self)
        self.label_model.grid(row=4, column=0, sticky="w", padx=10, pady=(10, 0))
        ttk.Combobox(self, values=self.app.MODELS, state="readonly",
                     textvariable=self.model_var).grid(row=5, column=0,
                                                       sticky="w", padx=10)

    
        self.btn_save = ttk.Button(self, command=self._save, style="Normal.TButton")
        self.btn_save.grid(row=6, column=0, sticky="e", padx=10, pady=10)

        self.update_idletasks()  
        
        px = self.app.root.winfo_rootx()
        py = self.app.root.winfo_rooty()
        pw = self.app.root.winfo_width()
        ph = self.app.root.winfo_height()
        ww = self.winfo_width()
        wh = self.winfo_height()
        x = px + (pw - ww) // 2
        y = py + (ph - wh) // 2
        self.geometry(f"+{x}+{y}")

    
    def _instant_theme(self, *_):
        if self.app.theme != self.theme_var.get():
            self.app.theme = self.theme_var.get()
            self.app._apply_theme()
            self._sync_theme()


    def _instant_lang(self, *_):
        if self.app.language != self.lang_var.get():
            self.app.language = self.lang_var.get()
            self.app._translate_ui()
            self._sync_lang()

    
    def _sync_theme(self):
        t = THEMES[self.app.theme]
        self.configure(bg=t["bg"])

        for key, rb in self.theme_buttons.items():
            rb.config(style="ActiveLang.TButton" if self.theme_var.get()==key else "Tool.TButton")

    def _sync_lang(self):
        _ = self.app._
        self.title(f'{_("app_name")} - {_("settings")}')
        self.label_theme.config(text=_("theme"))
        self.label_lang.config(text=_("language"))
        self.label_model.config(text=_("model"))
        self.btn_save.config(text=_("save"))
        for code, btn in self.lang_buttons.items():
            active = code == self.lang_var.get()
            btn.state(["pressed"] if active else ["!pressed"])
            btn.configure(style="ActiveLang.TButton" if active else "Tool.TButton")

        for key, rb in self.theme_buttons.items():
            rb.config(text=_(f"t_{key}"))
        
        

    
    def _save(self):
        self.app.handle_model(self.model_var.get())
        self.destroy()

if __name__ == "__main__":
    InspectorApp().run()
