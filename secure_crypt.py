import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

# --- IMPORTAR LA LIBRERÍA DE CRIPTOGRAFÍA ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# ------------------------------------------------------------
# MOTOR DE CIFRADO (VERSIÓN MEJORADA QUE GUARDA EL NOMBRE)
# ------------------------------------------------------------

def generar_claves_gui(nombre_usuario, password):
    """
    Genera un par de claves RSA de 2048 bits.
    La privada se protege con la contraseña que el usuario elija.
    """
    try:
        clave_privada = RSA.generate(2048)
        clave_publica = clave_privada.publickey()
        
        # Guardar clave pública
        with open(f"{nombre_usuario}_publica.pem", "wb") as f:
            f.write(clave_publica.export_key(format="PEM"))
        
        # Guardar clave privada (cifrada con la contraseña)
        if password:
            clave_privada_cifrada = clave_privada.export_key(
                format="PEM", 
                passphrase=password, 
                pkcs=8, 
                protection="scryptAndAES128-CBC"
            )
        else:
            clave_privada_cifrada = clave_privada.export_key(format="PEM")
        
        with open(f"{nombre_usuario}_privada.pem", "wb") as f:
            f.write(clave_privada_cifrada)
            
        return True, f"Claves generadas:\n{nombre_usuario}_publica.pem\n{nombre_usuario}_privada.pem"
    except Exception as e:
        return False, f"Error: {str(e)}"

def cifrar_archivo_gui(ruta_entrada, ruta_salida, ruta_clave_publica):
    """
    Cifra un archivo usando AES-256-GCM.
    ¡NUEVO! Guarda el nombre original dentro del paquete cifrado.
    """
    try:
        # Cargar la clave pública del receptor
        with open(ruta_clave_publica, "rb") as f:
            clave_publica = RSA.import_key(f.read())
        
        # 1. Preparar los datos a cifrar: [LONGITUD_NOMBRE(4 bytes)] + [NOMBRE] + [CONTENIDO]
        nombre_original = os.path.basename(ruta_entrada).encode('utf-8')
        with open(ruta_entrada, "rb") as f:
            contenido = f.read()
        
        # Construimos el paquete que se va a cifrar con AES
        datos_a_cifrar = len(nombre_original).to_bytes(4, 'big') + nombre_original + contenido
        
        # 2. Cifrado híbrido (AES + RSA)
        clave_aes = get_random_bytes(32)  # Clave AES de 256 bits
        nonce = get_random_bytes(12)      # Número usado una sola vez
        
        # Cifrar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(clave_publica)
        clave_aes_cifrada = cipher_rsa.encrypt(clave_aes)
        
        # Cifrar los datos con AES-GCM (incluye autenticación)
        cipher_aes = AES.new(clave_aes, AES.MODE_GCM, nonce=nonce)
        datos_cifrados, tag = cipher_aes.encrypt_and_digest(datos_a_cifrar)
        
        # 3. Guardar el archivo final:
        # [Largo_Clave_RSA(4)] + [Clave_RSA] + [Nonce] + [Tag] + [Datos_Cifrados]
        with open(ruta_salida, "wb") as f:
            f.write(len(clave_aes_cifrada).to_bytes(4, "big"))
            f.write(clave_aes_cifrada)
            f.write(nonce)
            f.write(tag)
            f.write(datos_cifrados)
        
        return True, f"✅ Archivo cifrado correctamente:\n{ruta_salida}", ruta_salida
    except Exception as e:
        return False, f"❌ Error al cifrar: {str(e)}", None

def descifrar_archivo_gui(ruta_entrada, carpeta_destino, ruta_clave_privada, password):
    """
    Descifra un archivo y RESTAURA EL NOMBRE ORIGINAL automáticamente.
    """
    try:
        # Cargar la clave privada
        with open(ruta_clave_privada, "rb") as f:
            clave_privada_bytes = f.read()
        clave_privada = RSA.import_key(clave_privada_bytes, passphrase=password)
        
        # Leer el archivo cifrado
        with open(ruta_entrada, "rb") as f:
            len_clave_aes_cifrada = int.from_bytes(f.read(4), "big")
            clave_aes_cifrada = f.read(len_clave_aes_cifrada)
            nonce = f.read(12)
            tag = f.read(16)
            datos_cifrados = f.read()
        
        # Descifrar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(clave_privada)
        clave_aes = cipher_rsa.decrypt(clave_aes_cifrada)
        
        # Descifrar los datos con AES-GCM
        cipher_aes = AES.new(clave_aes, AES.MODE_GCM, nonce=nonce)
        datos_descifrados = cipher_aes.decrypt_and_verify(datos_cifrados, tag)
        
        # --- NUEVO: Extraer el nombre original del paquete ---
        len_nombre = int.from_bytes(datos_descifrados[:4], "big")
        nombre_original = datos_descifrados[4:4+len_nombre].decode('utf-8')
        contenido = datos_descifrados[4+len_nombre:]
        
        # Guardar el archivo con su nombre original en la carpeta de destino
        ruta_final = os.path.join(carpeta_destino, nombre_original)
        
        # Si ya existe un archivo con ese nombre, le añadimos un número para no pisarlo
        contador = 1
        while os.path.exists(ruta_final):
            nombre_base, extension = os.path.splitext(nombre_original)
            nuevo_nombre = f"{nombre_base}_{contador}{extension}"
            ruta_final = os.path.join(carpeta_destino, nuevo_nombre)
            contador += 1
        
        with open(ruta_final, "wb") as f:
            f.write(contenido)
        
        return True, f"✅ Archivo descifrado correctamente:\n{ruta_final}", ruta_final
    except Exception as e:
        return False, f"❌ Error al descifrar: {str(e)}", None

# ------------------------------------------------------------
# INTERFAZ GRÁFICA (VENTANA AMIGABLE)
# ------------------------------------------------------------
class CifradorApp:
    def __init__(self, root):
        self.root = root
        root.title("🔐 Cifrador Híbrido (Guarda el nombre original)")
        root.geometry("650x580")
        root.resizable(False, False)

        # Estilo
        style = ttk.Style()
        style.configure("TButton", padding=5)
        style.configure("TLabel", padding=5)

        # ========== SECCIÓN 1: GENERAR CLAVES ==========
        frame_claves = ttk.LabelFrame(root, text="1. Generar tus Claves Públicas/Privadas", padding=10)
        frame_claves.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_claves, text="Nombre de usuario (ej: juan):").grid(row=0, column=0, sticky="w")
        self.entry_usuario = ttk.Entry(frame_claves, width=20)
        self.entry_usuario.grid(row=0, column=1, padx=5)

        ttk.Label(frame_claves, text="Contraseña (para tu clave privada):").grid(row=1, column=0, sticky="w")
        self.entry_pass = ttk.Entry(frame_claves, width=20, show="*")
        self.entry_pass.grid(row=1, column=1, padx=5)

        self.btn_generar = ttk.Button(frame_claves, text="🔑 Generar Claves", command=self.generar_claves)
        self.btn_generar.grid(row=0, column=2, rowspan=2, padx=10)

        # ========== SECCIÓN 2: CIFRAR ==========
        frame_cifrar = ttk.LabelFrame(root, text="2. Cifrar un Archivo (para enviar a otro)", padding=10)
        frame_cifrar.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_cifrar, text="Archivo a cifrar:").grid(row=0, column=0, sticky="w")
        self.entry_archivo = ttk.Entry(frame_cifrar, width=40)
        self.entry_archivo.grid(row=0, column=1, padx=5)
        ttk.Button(frame_cifrar, text="📂 Buscar", command=self.seleccionar_archivo).grid(row=0, column=2)

        ttk.Label(frame_cifrar, text="Clave Pública del Receptor:").grid(row=1, column=0, sticky="w")
        self.entry_clave_pub = ttk.Entry(frame_cifrar, width=40)
        self.entry_clave_pub.grid(row=1, column=1, padx=5)
        ttk.Button(frame_cifrar, text="📂 Buscar", command=self.seleccionar_pub).grid(row=1, column=2)

        ttk.Button(frame_cifrar, text="🔒 CIFRAR ARCHIVO", command=self.ejecutar_cifrar).grid(row=2, column=1, pady=5)

        # ========== SECCIÓN 3: DESCIFRAR ==========
        frame_descifrar = ttk.LabelFrame(root, text="3. Descifrar un Archivo (recibido de otro)", padding=10)
        frame_descifrar.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_descifrar, text="Archivo cifrado (.enc):").grid(row=0, column=0, sticky="w")
        self.entry_archivo_enc = ttk.Entry(frame_descifrar, width=40)
        self.entry_archivo_enc.grid(row=0, column=1, padx=5)
        ttk.Button(frame_descifrar, text="📂 Buscar", command=self.seleccionar_enc).grid(row=0, column=2)

        ttk.Label(frame_descifrar, text="Tu Clave Privada:").grid(row=1, column=0, sticky="w")
        self.entry_clave_priv = ttk.Entry(frame_descifrar, width=40)
        self.entry_clave_priv.grid(row=1, column=1, padx=5)
        ttk.Button(frame_descifrar, text="📂 Buscar", command=self.seleccionar_priv).grid(row=1, column=2)

        ttk.Label(frame_descifrar, text="Contraseña de tu Privada:").grid(row=2, column=0, sticky="w")
        self.entry_pass_desc = ttk.Entry(frame_descifrar, width=40, show="*")
        self.entry_pass_desc.grid(row=2, column=1, padx=5)

        ttk.Button(frame_descifrar, text="🔓 DESCIFRAR ARCHIVO", command=self.ejecutar_descifrar).grid(row=3, column=1, pady=5)

        # ========== ÁREA DE LOG / MENSAJES ==========
        self.texto_log = tk.Text(root, height=8, bg="#f0f0f0", wrap=tk.WORD)
        self.texto_log.pack(fill="both", padx=10, pady=10, expand=True)
        self.texto_log.insert(tk.END, "Bienvenido. Selecciona las opciones con los botones.\n")
        self.texto_log.insert(tk.END, "🔹 NUEVO: Al descifrar, el programa restaurará el nombre original del archivo.\n")
        self.texto_log.config(state=tk.DISABLED)

    # --- Métodos para manejar la interfaz ---
    def log(self, mensaje):
        self.texto_log.config(state=tk.NORMAL)
        self.texto_log.insert(tk.END, mensaje + "\n")
        self.texto_log.see(tk.END)
        self.texto_log.config(state=tk.DISABLED)

    def seleccionar_archivo(self):
        ruta = filedialog.askopenfilename(title="Selecciona el archivo a cifrar")
        if ruta:
            self.entry_archivo.delete(0, tk.END)
            self.entry_archivo.insert(0, ruta)

    def seleccionar_pub(self):
        ruta = filedialog.askopenfilename(title="Selecciona la clave pública del receptor", filetypes=[("PEM files", "*.pem")])
        if ruta:
            self.entry_clave_pub.delete(0, tk.END)
            self.entry_clave_pub.insert(0, ruta)

    def seleccionar_enc(self):
        ruta = filedialog.askopenfilename(title="Selecciona el archivo cifrado (.enc)", filetypes=[("Encrypted files", "*.enc")])
        if ruta:
            self.entry_archivo_enc.delete(0, tk.END)
            self.entry_archivo_enc.insert(0, ruta)

    def seleccionar_priv(self):
        ruta = filedialog.askopenfilename(title="Selecciona tu clave privada", filetypes=[("PEM files", "*.pem")])
        if ruta:
            self.entry_clave_priv.delete(0, tk.END)
            self.entry_clave_priv.insert(0, ruta)

    def generar_claves(self):
        usuario = self.entry_usuario.get().strip()
        password = self.entry_pass.get()
        if not usuario:
            messagebox.showerror("Error", "Escribe un nombre de usuario.")
            return
        self.log(f"⏳ Generando claves para '{usuario}'...")
        ok, msg = generar_claves_gui(usuario, password if password else None)
        self.log(msg)
        if ok:
            messagebox.showinfo("Éxito", msg)

    def ejecutar_cifrar(self):
        entrada = self.entry_archivo.get()
        pub = self.entry_clave_pub.get()
        if not entrada or not pub:
            messagebox.showerror("Error", "Selecciona el archivo y la clave pública.")
            return
        # El archivo .enc se guarda en la misma carpeta que el original
        dir_base = os.path.dirname(entrada)
        nombre_base = os.path.basename(entrada)
        salida = os.path.join(dir_base, os.path.splitext(nombre_base)[0] + ".enc")
        
        self.log(f"⏳ Cifrando {nombre_base} ...")
        ok, msg, salida = cifrar_archivo_gui(entrada, salida, pub)
        self.log(msg)
        if ok:
            messagebox.showinfo("Completado", f"Archivo cifrado como:\n{salida}")

    def ejecutar_descifrar(self):
        entrada = self.entry_archivo_enc.get()
        priv = self.entry_clave_priv.get()
        password = self.entry_pass_desc.get()
        if not entrada or not priv:
            messagebox.showerror("Error", "Selecciona el archivo cifrado y tu clave privada.")
            return
        
        # Lo guardará en la misma carpeta donde está el archivo .enc
        carpeta_destino = os.path.dirname(entrada)
        
        self.log(f"⏳ Descifrando {os.path.basename(entrada)} ...")
        ok, msg, salida = descifrar_archivo_gui(entrada, carpeta_destino, priv, password)
        self.log(msg)
        if ok:
            messagebox.showinfo("Completado", f"Archivo descifrado como:\n{salida}")

# ------------------------------------------------------------
# EJECUTAR LA VENTANA
# ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = CifradorApp(root)
    root.mainloop()