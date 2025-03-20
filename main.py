import os
import socket
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox

# -------------------------------------------------------------------------
# CONFIGURAÇÃO DAS MÁQUINAS
# -------------------------------------------------------------------------
# Aqui definimos uma lista de dicionários com as máquinas do laboratório.
# Ajuste nome, IP, MAC, usuário admin e senha (para PsExec).
LAB_MACHINES = [
    {
        "name": "PC1",
        "ip": "192.168.0.101",
        "mac": "AA:BB:CC:DD:EE:01",
        "admin_user": "Administrador",
        "admin_pass": "Senha123",
    },
    {
        "name": "PC2",
        "ip": "192.168.0.102",
        "mac": "AA:BB:CC:DD:EE:02",
        "admin_user": "Administrador",
        "admin_pass": "Senha123",
    },
    # Adicione quantas quiser
]


# -------------------------------------------------------------------------
# 1) FUNÇÃO PARA WAKE ON LAN
# -------------------------------------------------------------------------
def wake_on_lan(mac_address, broadcast_ip="255.255.255.255", port=9):
    """
    Envia pacote mágico (WOL) para o endereço MAC especificado.
    As máquinas devem ter o Wake-on-LAN habilitado na BIOS e no Windows.
    """
    # Remove ':' ou '-' do MAC
    mac_address = mac_address.replace(":", "").replace("-", "")
    if len(mac_address) != 12:
        raise ValueError("Endereço MAC inválido: " + mac_address)

    # Cria o pacote mágico: 6 bytes 0xFF + 16x o MAC
    magic_packet = b"\xff" * 6 + (bytes.fromhex(mac_address) * 16)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (broadcast_ip, port))


# -------------------------------------------------------------------------
# 2) FUNÇÕES PARA CONFIGURAR LOGIN AUTOMÁTICO
# -------------------------------------------------------------------------
def set_autologon_via_psexec(pc_name, admin_user, admin_pass, aluno_user, aluno_pass):
    """
    Configura no registro do Windows (remotamente) a chave para login automático.
    Usamos PsExec para rodar 'reg add' no PC de destino.
    Ao reiniciar, ele fará login automático com as credenciais do 'aluno'.
    """
    # Comando base do PsExec
    # -h eleva privilégios (no Win10+ se UAC estiver ativado)
    # \\pc_name = nome (ou IP) da máquina remota
    base_cmd = f'psexec \\\\{pc_name} -u "{admin_user}" -p "{admin_pass}" -h'

    # 1) Define DefaultUserName
    cmd_user = (
        base_cmd
        + r' reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'
        + f' /v DefaultUserName /t REG_SZ /d "{aluno_user}" /f'
    )

    # 2) Define DefaultPassword
    cmd_pass = (
        base_cmd
        + r' reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'
        + f' /v DefaultPassword /t REG_SZ /d "{aluno_pass}" /f'
    )

    # 3) Define AutoAdminLogon
    cmd_autolog = (
        base_cmd
        + r' reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'
        + r' /v AutoAdminLogon /t REG_SZ /d "1" /f'
    )

    # Executa cada comando (você pode capturar saída, tratar erros etc.)
    subprocess.call(cmd_user, shell=True)
    subprocess.call(cmd_pass, shell=True)
    subprocess.call(cmd_autolog, shell=True)


def configure_autologon_for_all(aluno_user, aluno_pass):
    """
    Aplica a configuração de auto-logon em todas as máquinas do LAB_MACHINES.
    """
    for m in LAB_MACHINES:
        # Usando o IP como nome remoto (pode usar hostname também)
        pc_name = m["ip"]
        admin_user = m["admin_user"]
        admin_pass = m["admin_pass"]
        set_autologon_via_psexec(
            pc_name, admin_user, admin_pass, aluno_user, aluno_pass
        )


# -------------------------------------------------------------------------
# 3) FUNÇÃO PARA ABRIR UMA APLICAÇÃO REMOTAMENTE (PSExec)
# -------------------------------------------------------------------------
def open_app_remote(pc_name, admin_user, admin_pass, app_path):
    """
    Abre uma aplicação (EXE) na máquina remota.
    -i faz rodar de modo interativo na sessão 0 (cuidado em qual sessão).
    Em muitos casos, precisa de -i para que o app apareça na área de trabalho real.
    """
    cmd = (
        f'psexec \\\\{pc_name} -u "{admin_user}" -p "{admin_pass}" -h '
        + f'-i "{app_path}"'
    )
    subprocess.call(cmd, shell=True)


def open_application_on_all(app_path):
    """
    Abre a aplicação em todas as máquinas listadas em LAB_MACHINES.
    """
    for m in LAB_MACHINES:
        pc_name = m["ip"]
        admin_user = m["admin_user"]
        admin_pass = m["admin_pass"]
        open_app_remote(pc_name, admin_user, admin_pass, app_path)


# -------------------------------------------------------------------------
# 4) FUNÇÃO PARA COMPARTILHAR (ENVIAR) ARQUIVOS
# -------------------------------------------------------------------------
def copy_file_to_remote(pc_name, admin_user, admin_pass, local_src, remote_dst):
    """
    Usa PsExec para chamar xcopy ou copy no remoto.
    Exemplo:
        xcopy \\MEU-SERVIDOR\compartilhamento\arquivo.exe C:\Destino /Y
    Você pode adaptar para caminhos de rede, etc.
    """
    # Observação: se local_src for um caminho local na máquina controladora,
    # precisamos primeiro mapeá-lo como recurso de rede acessível pela máquina remota
    # ou usar caminhos UNC (\\controlador\c$\pasta\arquivo).
    # Exemplo abaixo assume que local_src já é caminho UNC de rede.
    cmd = (
        f'psexec \\\\{pc_name} -u "{admin_user}" -p "{admin_pass}" -h '
        + f'xcopy "{local_src}" "{remote_dst}" /Y'
    )
    subprocess.call(cmd, shell=True)


def copy_file_to_all(local_src, remote_dst):
    """
    Copia o arquivo 'local_src' (precisa ser caminho de rede acessível)
    para 'remote_dst' em todas as máquinas do LAB_MACHINES.
    """
    for m in LAB_MACHINES:
        pc_name = m["ip"]
        admin_user = m["admin_user"]
        admin_pass = m["admin_pass"]
        copy_file_to_remote(pc_name, admin_user, admin_pass, local_src, remote_dst)


# -------------------------------------------------------------------------
# GUI COM TKINTER
# -------------------------------------------------------------------------
class LabManagerApp:
    def __init__(self, master):
        self.master = master
        master.title("Gerenciador de Laboratório - Exemplo")

        # Botão 1: Ligar máquinas (WOL)
        self.btn_ligar = tk.Button(
            master, text="Ligar Máquinas (WOL)", command=self.ligar_maquinas
        )
        self.btn_ligar.pack(pady=5)

        # Botão 2: Configurar Auto-Logon
        frame_autolog = tk.Frame(master)
        tk.Label(frame_autolog, text="Usuário Aluno:").pack(side=tk.LEFT)
        self.entry_aluno_user = tk.Entry(frame_autolog)
        self.entry_aluno_user.insert(0, "aluno1")  # valor padrão
        self.entry_aluno_user.pack(side=tk.LEFT, padx=5)

        tk.Label(frame_autolog, text="Senha:").pack(side=tk.LEFT)
        self.entry_aluno_pass = tk.Entry(frame_autolog, show="*")
        self.entry_aluno_pass.insert(0, "senha1")  # valor padrão
        self.entry_aluno_pass.pack(side=tk.LEFT, padx=5)

        frame_autolog.pack(pady=5)

        self.btn_autologon = tk.Button(
            master,
            text="Configurar Auto-Logon (reinício necessário)",
            command=self.configurar_autologon,
        )
        self.btn_autologon.pack(pady=5)

        # Botão 3: Abrir Aplicação
        frame_app = tk.Frame(master)
        tk.Label(frame_app, text="Caminho da aplicação:").pack(side=tk.LEFT)
        self.entry_app_path = tk.Entry(frame_app, width=40)
        self.entry_app_path.insert(0, r"C:\Windows\System32\notepad.exe")
        self.entry_app_path.pack(side=tk.LEFT, padx=5)

        frame_app.pack(pady=5)

        self.btn_open_app = tk.Button(
            master,
            text="Abrir Aplicação em Todas as Máquinas",
            command=self.abrir_aplicacao_todas,
        )
        self.btn_open_app.pack(pady=5)

        # Botão 4: Compartilhar Arquivo
        frame_file = tk.Frame(master)
        tk.Label(frame_file, text="Arquivo Local (rede):").pack(side=tk.LEFT)
        self.entry_file_local = tk.Entry(frame_file, width=40)
        self.entry_file_local.pack(side=tk.LEFT, padx=5)
        btn_browse = tk.Button(
            frame_file, text="...", command=self.escolher_arquivo_local
        )
        btn_browse.pack(side=tk.LEFT)
        frame_file.pack(pady=5)

        frame_dest = tk.Frame(master)
        tk.Label(frame_dest, text="Destino Remoto:").pack(side=tk.LEFT)
        self.entry_file_remote = tk.Entry(frame_dest, width=40)
        self.entry_file_remote.insert(0, r"C:\Destino\arquivo.exe")
        self.entry_file_remote.pack(side=tk.LEFT, padx=5)
        frame_dest.pack(pady=5)

        self.btn_copy_file = tk.Button(
            master,
            text="Enviar Arquivo para Todas as Máquinas",
            command=self.enviar_arquivo_todas,
        )
        self.btn_copy_file.pack(pady=5)

    # --------------------------
    # AÇÕES DO GUI
    # --------------------------
    def ligar_maquinas(self):
        """Envia pacote WOL para cada máquina da lista."""
        try:
            for m in LAB_MACHINES:
                wake_on_lan(m["mac"])
            messagebox.showinfo(
                "Sucesso", "Pacotes WOL enviados para todas as máquinas."
            )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao enviar WOL: {e}")

    def configurar_autologon(self):
        """Configura auto-logon em todas as máquinas."""
        aluno_user = self.entry_aluno_user.get()
        aluno_pass = self.entry_aluno_pass.get()
        try:
            configure_autologon_for_all(aluno_user, aluno_pass)
            messagebox.showinfo(
                "Concluído", "Auto-logon configurado (requer reboot das máquinas)."
            )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao configurar auto-logon: {e}")

    def abrir_aplicacao_todas(self):
        """Abre a aplicação em todas as máquinas."""
        app_path = self.entry_app_path.get()
        try:
            open_application_on_all(app_path)
            messagebox.showinfo("Concluído", "Aplicação iniciada em todas as máquinas.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao abrir aplicação: {e}")

    def escolher_arquivo_local(self):
        """Abre diálogo para escolher arquivo local (idealmente um caminho acessível via rede)."""
        filename = filedialog.askopenfilename()
        if filename:
            self.entry_file_local.delete(0, tk.END)
            self.entry_file_local.insert(0, filename)

    def enviar_arquivo_todas(self):
        """Envia arquivo para todas as máquinas."""
        local_src = self.entry_file_local.get()  # Caminho local (ou UNC)
        remote_dst = (
            self.entry_file_remote.get()
        )  # Caminho de destino na máquina remota

        if not os.path.exists(local_src):
            # Se for caminho local, verificamos se existe. Se for UNC, pode não existir localmente.
            # Se for um caminho de rede, esse check não funcionará necessariamente.
            # Mas vamos avisar mesmo assim.
            ans = messagebox.askyesno(
                "Atenção",
                "O arquivo local não existe. Se for um caminho de rede UNC, deseja continuar mesmo assim?",
            )
            if not ans:
                return

        try:
            copy_file_to_all(local_src, remote_dst)
            messagebox.showinfo("Concluído", "Arquivo enviado para todas as máquinas.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao enviar arquivo: {e}")


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    root = tk.Tk()
    app = LabManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
