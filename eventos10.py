import streamlit as st
from datetime import datetime, time
import pandas as pd
import os
from PIL import Image
import tempfile
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import paramiko
import json
import ssl
import re
import time as time_module
import csv
from email.mime.base import MIMEBase
from email import encoders
from io import StringIO
from email.utils import formatdate
import threading
from functools import wraps

from datetime import datetime, time, timezone
import pytz  # Necesitarás instalar esta librería: pip install pytz

# ====================
# CONCURRENCY MANAGER
# ====================
class ConcurrencyManager:
    _instance = None
    _locks = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConcurrencyManager, cls).__new__(cls)
        return cls._instance

    def get_lock(self, resource_name):
        if resource_name not in self._locks:
            self._locks[resource_name] = threading.Lock()
        return self._locks[resource_name]

def synchronized(resource_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            manager = ConcurrencyManager()
            lock = manager.get_lock(resource_name)
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return decorator

# ====================
# CONFIGURACIÓN INICIAL
# ====================
class Config:
    def __init__(self):
        # SMTP Configuration
        self.SMTP_SERVER = st.secrets["smtp_server"]
        self.SMTP_PORT = st.secrets["smtp_port"]
        self.EMAIL_USER = st.secrets["email_user"]
        self.EMAIL_PASSWORD = st.secrets["email_password"]
        self.NOTIFICATION_EMAIL = st.secrets["notification_email"]
        self.MAX_FILE_SIZE_MB = 10
        self.TIMEOUT_SECONDS = 30
        
        # SFTP Configuration
        self.REMOTE = {
            'HOST': st.secrets["remote_host"],
            'USER': st.secrets["remote_user"],
            'PASSWORD': st.secrets["remote_password"],
            'PORT': st.secrets["remote_port"],
            'DIR': st.secrets["remote_dir"],
            'TIMEOUT_SECONDS': 30
        }
        
        # File Configuration
        self.FILES = {
            "enfermeras": st.secrets["file_enfermeras2"],  # aus_asistencia_enfermeras.csv
            "claves": st.secrets["file_creacion_enfermeras2"],   
            "pacientes": st.secrets["file_pacientes2"],    # aus_asistencia_pacientes.csv
            "evento": st.secrets["file_eventos2"]         # aus_evento_adverso.csv
        }
        
        # App Configuration
        self.SUPERVISOR_MODE = st.secrets.get("supervisor_mode", True)
        self.DEBUG_MODE = st.secrets.get("debug_mode", False)

CONFIG = Config()

# ==================
# FUNCIONES SSH/SFTP
# ==================
class SSHManager:
    @staticmethod
    def get_connection():
        """Establece conexión SSH segura"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=CONFIG.REMOTE['HOST'],
                port=CONFIG.REMOTE['PORT'],
                username=CONFIG.REMOTE['USER'],
                password=CONFIG.REMOTE['PASSWORD'],
                timeout=CONFIG.REMOTE['TIMEOUT_SECONDS'],
                banner_timeout=30
            )
            return ssh
        except Exception as e:
            st.error(f"Error de conexión SSH: {str(e)}")
            if CONFIG.DEBUG_MODE:
                st.error(f"Detalles conexión: Host={CONFIG.REMOTE['HOST']}:{CONFIG.REMOTE['PORT']} User={CONFIG.REMOTE['USER']}")
            return None

    @staticmethod
    def upload_file(local_path, remote_filename, numero_economico=None):
        """Sube un archivo al servidor remoto con manejo de concurrencia"""
        max_retries = 3
        for attempt in range(max_retries):
            ssh = SSHManager.get_connection()
            if not ssh:
                if attempt < max_retries - 1:
                    time_module.sleep(2)
                    continue
                return False

            try:
                sftp = ssh.open_sftp()

                # Determinar el directorio destino
                if numero_economico:
                    # Para archivos de usuario, usar directorio específico
                    user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{numero_economico}/"
                    remote_path = os.path.join(user_dir, remote_filename)

                    # Crear directorio del usuario si no existe
                    try:
                        sftp.stat(user_dir)
                    except FileNotFoundError:
                        SSHManager._create_remote_dirs(sftp, user_dir)
                else:
                    # Para archivos del sistema, usar directorio principal
                    remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

                sftp.put(local_path, remote_path)
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    time_module.sleep(2)
                    continue
                st.error(f"Error subiendo archivo después de {max_retries} intentos: {str(e)}")
                if CONFIG.DEBUG_MODE:
                    st.error(f"Ruta remota intentada: {remote_path}")
                return False
            finally:
                try:
                    ssh.close()
                except:
                    pass

    @staticmethod
    def get_remote_file(remote_filename, numero_economico=None):
        """Lee archivo remoto con manejo de errores"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return None

        try:
            sftp = ssh.open_sftp()
            
            # Determinar el directorio origen
            if numero_economico:
                # Para archivos de usuario, usar directorio específico
                user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{numero_economico}/"
                remote_path = os.path.join(user_dir, remote_filename)
            else:
                # Para archivos del sistema, usar directorio principal
                remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

            if CONFIG.DEBUG_MODE:
                st.info(f"Intentando leer archivo remoto: {remote_path}")

            file_stats = sftp.stat(remote_path)
            st.info(f"Tamaño del archivo: {file_stats.st_size} bytes")

            with sftp.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8')

            if CONFIG.DEBUG_MODE:
                st.info(f"Archivo leído correctamente. Tamaño: {len(content)} bytes")

            return content
        except FileNotFoundError:
            st.error(f"Archivo no encontrado en servidor: {remote_filename}")
            if CONFIG.DEBUG_MODE:
                st.error(f"Contenido del directorio remoto:")
                try:
                    dir_path = user_dir if numero_economico else CONFIG.REMOTE['DIR']
                    files = sftp.listdir(dir_path)
                    st.write(files)
                except Exception as e:
                    st.error(f"Error listando directorio: {str(e)}")
            return None
        except Exception as e:
            st.error(f"Error leyendo archivo remoto: {str(e)}")
            return None
        finally:
            ssh.close()

    @staticmethod
    def list_remote_files(pattern=None, numero_economico=None):
        """Lista archivos en el directorio remoto"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return []

        try:
            sftp = ssh.open_sftp()
            
            # Determinar el directorio a listar
            if numero_economico:
                # Para archivos de usuario, usar directorio específico
                dir_path = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{numero_economico}/"
            else:
                # Para archivos del sistema, usar directorio principal
                dir_path = CONFIG.REMOTE['DIR']

            # Verificar si el directorio existe
            try:
                sftp.stat(dir_path)
                files = sftp.listdir(dir_path)
            except FileNotFoundError:
                return []

            if pattern:
                import fnmatch
                files = [f for f in files if fnmatch.fnmatch(f, pattern)]

            return files
        except Exception as e:
            st.error(f"Error listando archivos remotos: {str(e)}")
            return []
        finally:
            ssh.close()

    @staticmethod
    def delete_remote_file(remote_filename, numero_economico=None):
        """Elimina un archivo remoto"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return False

        try:
            sftp = ssh.open_sftp()
            
            # Determinar el directorio
            if numero_economico:
                # Para archivos de usuario, usar directorio específico
                user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{numero_economico}/"
                remote_path = os.path.join(user_dir, remote_filename)
            else:
                # Para archivos del sistema, usar directorio principal
                remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)
                
            sftp.remove(remote_path)
            return True
        except Exception as e:
            st.error(f"Error eliminando archivo remoto: {str(e)}")
            return False
        finally:
            ssh.close()

    @staticmethod
    def put_remote_file(remote_path, content, numero_economico=None):
        """Escribe archivo remoto con manejo de errores, creando directorios si no existen"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return False

        try:
            sftp = ssh.open_sftp()

            # Determinar el directorio destino
            if numero_economico:
                # Para archivos de usuario, usar directorio específico
                user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{numero_economico}/"
                full_remote_path = os.path.join(user_dir, os.path.basename(remote_path))

                # Crear directorio del usuario si no existe
                try:
                    sftp.stat(user_dir)
                except FileNotFoundError:
                    SSHManager._create_remote_dirs(sftp, user_dir)
            else:
                # Para archivos del sistema, usar directorio principal
                full_remote_path = os.path.join(CONFIG.REMOTE['DIR'], os.path.basename(remote_path))

            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                sftp.put(temp_file_path, full_remote_path)
                if CONFIG.DEBUG_MODE:
                    st.info(f"Archivo subido exitosamente: {full_remote_path}")
                return True
            except Exception as e:
                st.error(f"Error subiendo archivo al servidor: {str(e)}")
                return False
            finally:
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
        except Exception as e:
            st.error(f"Error en operación SFTP: {str(e)}")
            return False
        finally:
            try:
                ssh.close()
            except:
                pass

    @staticmethod
    def _create_remote_dirs(sftp, remote_dir):
        """Función auxiliar para crear directorios remotos recursivamente"""
        if remote_dir == '' or remote_dir == '/':
            return

        parent_dir = os.path.dirname(remote_dir)
        if parent_dir and parent_dir != '/':
            try:
                sftp.listdir(parent_dir)
            except (IOError, OSError):
                SSHManager._create_remote_dirs(sftp, parent_dir)

        try:
            sftp.mkdir(remote_dir)
        except (IOError, OSError):
            # El directorio ya existe, podemos ignorar el error
            pass

    @staticmethod
    def check_connection():
        """Verifica si la conexión SSH está activa"""
        ssh = SSHManager.get_connection()
        if ssh:
            ssh.close()
            return True
        return False

    @staticmethod
    def test_connection():
        """Prueba la conexión y muestra información de diagnóstico"""
        try:
            ssh = SSHManager.get_connection()
            if not ssh:
                return False
            
            try:
                sftp = ssh.open_sftp()
                
                # Probar acceso al directorio principal
                try:
                    files = sftp.listdir(CONFIG.REMOTE['DIR'])
                    st.success(f"✅ Conexión SSH exitosa. Directorio: {CONFIG.REMOTE['DIR']}")
                    st.info(f"Archivos en directorio principal: {len(files)}")
                except Exception as e:
                    st.error(f"❌ No se puede acceder al directorio principal: {str(e)}")
                
                # Probar creación de directorio de usuario
                test_user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/test_user/"
                try:
                    sftp.stat(test_user_dir)
                    st.info("✅ Directorio de usuario ya existe")
                except FileNotFoundError:
                    try:
                        sftp.mkdir(test_user_dir)
                        st.info("✅ Directorio de usuario creado exitosamente")
                        # Limpiar directorio de prueba
                        sftp.rmdir(test_user_dir)
                    except Exception as e:
                        st.error(f"❌ Error creando directorio de usuario: {str(e)}")
                
                return True
                
            finally:
                ssh.close()
                
        except Exception as e:
            st.error(f"❌ Error en prueba de conexión: {str(e)}")
            return False

# ====================
# FUNCIONES DE AUTENTICACIÓN
# ====================
@synchronized("log_files")
def mover_logs_jornada_anterior(user_info):
    """Mueve los logs de la jornada anterior a la carpeta principal de user_logs_eventos"""
    try:
        ssh = SSHManager.get_connection()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor")
            return False

        sftp = ssh.open_sftp()

        # Directorio origen: carpeta específica del usuario
        user_dir = f"/home/POLANCO6/AUSENTISMO2/user_logs_eventos/{user_info['numero_economico']}/"

        # Directorio destino: carpeta principal de logs
        main_log_dir = "/home/POLANCO6/AUSENTISMO2/user_logs_eventos/"

        if CONFIG.DEBUG_MODE:
            st.info(f"📁 Directorio origen: {user_dir}")
            st.info(f"📁 Directorio destino: {main_log_dir}")

        try:
            # Verificar si existe el directorio del usuario
            sftp.stat(user_dir)

            # Listar todos los archivos en el directorio del usuario
            archivos = sftp.listdir(user_dir)

            if not archivos:
                if CONFIG.DEBUG_MODE:
                    st.info("📝 No hay archivos de log para mover")
                return True

            movidos_count = 0
            errores_count = 0

            for archivo in archivos:
                origen_path = os.path.join(user_dir, archivo)
                destino_path = os.path.join(main_log_dir, archivo)

                if CONFIG.DEBUG_MODE:
                    st.info(f"🔧 Intentando mover: {origen_path} -> {destino_path}")

                # Mover el archivo
                try:
                    sftp.rename(origen_path, destino_path)
                    movidos_count += 1
                    if CONFIG.DEBUG_MODE:
                        st.success(f"✅ Movido: {archivo}")
                except Exception as e:
                    errores_count += 1
                    st.warning(f"⚠️ No se pudo mover {archivo}: {str(e)}")
                    if CONFIG.DEBUG_MODE:
                        st.error(f"Detalles del error: {type(e).__name__}")

            if CONFIG.DEBUG_MODE:
                st.success(f"✅ Se movieron {movidos_count} archivos de log")
                if errores_count > 0:
                    st.warning(f"⚠️ Hubo {errores_count} errores al mover archivos")

            return movidos_count > 0 or errores_count == 0

        except FileNotFoundError:
            if CONFIG.DEBUG_MODE:
                st.info("📝 No existe directorio de usuario para mover logs")
            return True

        except Exception as e:
            st.error(f"❌ Error moviendo logs: {str(e)}")
            if CONFIG.DEBUG_MODE:
                import traceback
                st.error(f"Traceback completo: {traceback.format_exc()}")
            return False

        finally:
            sftp.close()
            ssh.close()

    except Exception as e:
        st.error(f"❌ Error en operación de mover logs: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return False

def manejar_inicio_jornada(user_info):
    """Maneja la pregunta de inicio de jornada laboral"""
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🏥 Inicio de Jornada")

    # Verificar si ya se respondió hoy
    hoy = datetime.now().strftime("%Y-%m-%d")
    if 'ultimo_inicio_jornada' in st.session_state and st.session_state.ultimo_inicio_jornada == hoy:
        st.sidebar.info("✅ Jornada ya iniciada hoy")
        return

    respuesta = st.sidebar.radio(
        "¿Estás iniciando tu jornada laboral?",
        ["No", "Sí"],
        index=0
    )

    if respuesta == "Sí":
        if st.sidebar.button("🔒 Confirmar Inicio de Jornada", use_container_width=True):
            with st.spinner("Procesando inicio de jornada..."):
                # Mover logs de jornada anterior
                if mover_logs_jornada_anterior(user_info):
                    st.session_state.ultimo_inicio_jornada = hoy
                    st.sidebar.success("🎉 Jornada iniciada correctamente")
                    st.sidebar.info("📁 Logs de jornadas anteriores movidos a la carpeta principal")

                    # Mostrar información de diagnóstico
                    if CONFIG.DEBUG_MODE:
                        st.sidebar.info("🔍 Modo debug: Verificando movimiento de archivos...")
                        # Listar archivos en el directorio principal para confirmar
                        try:
                            ssh = SSHManager.get_connection()
                            if ssh:
                                sftp = ssh.open_sftp()
                                main_dir = "/home/POLANCO6/AUSENTISMO2/user_logs_eventos/"
                                archivos_principales = sftp.listdir(main_dir)
                                st.sidebar.info(f"📊 Archivos en directorio principal: {len(archivos_principales)}")
                                sftp.close()
                                ssh.close()
                        except Exception as e:
                            st.sidebar.warning(f"⚠️ No se pudo verificar directorio principal: {str(e)}")
                else:
                    st.sidebar.error("❌ Error moviendo logs de jornada anterior")
    else:
        st.sidebar.info("➡️ Continuando con sesión actual")

def load_csv_data(filename, numero_economico=None):
    """Carga datos desde un archivo CSV remoto"""
    if CONFIG.DEBUG_MODE:
        st.info(f"Cargando archivo: {filename}")

    # Para archivos del sistema (enfermeras, claves, pacientes), usar directorio principal (sin numero_economico)
    csv_content = SSHManager.get_remote_file(filename, None)

    if not csv_content:
        st.error(f"No se pudo cargar el archivo {filename}")
        return None

    try:
        # Convertir a DataFrame
        df = pd.read_csv(StringIO(csv_content))

        # Limpiar espacios en blanco en todas las columnas de tipo string
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].astype(str).str.strip()

        if CONFIG.DEBUG_MODE:
            st.info(f"Archivo {filename} cargado correctamente. Filas: {len(df)}")
            st.info("Columnas disponibles:")
            st.write(df.columns.tolist())
            if 'numero_economico' in df.columns:
                st.info("Valores únicos en columna 'numero_economico':")
                st.write(df['numero_economico'].astype(str).unique())

        return df
    except Exception as e:
        st.error(f"Error procesando archivo {filename}: {str(e)}")
        if CONFIG.DEBUG_MODE:
            st.text("Contenido crudo (primeras 10 líneas):")
            st.text("\n".join(csv_content.split("\n")[:10]))
        return None

# ====================
# FUNCIONES PRINCIPALES (CORREGIDAS)
# ====================

def save_report_to_json(report_data, user_info):
    """Guarda el reporte en formato JSON con el nuevo formato de nombre en el directorio del usuario"""
    try:
        # Obtener datos necesarios para el nombre del archivo
        turno_laboral = obtener_turno_laboral(user_info)
        servicio = obtener_servicio_usuario(user_info)

        if not servicio or not turno_laboral:
            st.error("❌ No se pudieron obtener todos los datos necesarios para el nombre del archivo")
            if CONFIG.DEBUG_MODE:
                st.error(f"servicio: {servicio}, turno_laboral: {turno_laboral}")
            return False

        # Limpiar y formatear los valores - eliminar caracteres problemáticos
        servicio = servicio.strip().replace(' ', '_').replace('(', '').replace(')', '').replace(':', '').replace('/', '_')
        numero_economico = user_info['numero_economico'].strip()
        turno_laboral = turno_laboral.strip().replace(' ', '_').replace('(', '').replace(')', '').replace(':', '').replace('/', '_')

        # Obtener fecha y hora actual en formato YY-MM-DD-HH-MM-SS
        fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
        fecha_formateada = fecha_actual.strftime("%y-%m-%d")
        hora_formateada = fecha_actual.strftime("%H-%M-%S-%f")[:-3]  # Quitar últimos 3 dígitos de microsegundos

        # Crear nombre de archivo con timestamp para evitar colisiones
        filename = f"{fecha_formateada}.{hora_formateada}.{servicio}.{numero_economico}.{turno_laboral}.json"

        if CONFIG.DEBUG_MODE:
            st.info(f"📁 Nombre de archivo generado: {filename}")

        # Añadir información del usuario que reporta
        report_data['metadata'] = {
            'reportado_por': user_info['nombre'],
            'numero_economico': user_info['numero_economico'],
            'puesto': user_info['puesto'],
            'fecha_reporte': datetime.now(pytz.timezone('America/Mexico_City')).strftime("%Y-%m-%d %H:%M:%S"),
            'archivo': filename,
            'servicio': servicio,
            'turno_laboral': turno_laboral,
            'timestamp': fecha_actual.timestamp()  # Añadir timestamp único
        }

        # Guardar archivo localmente temporalmente
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as tmp_file:
            json.dump(report_data, tmp_file, ensure_ascii=False, indent=2)
            temp_filename = tmp_file.name

        # Subir al servidor remoto en el directorio del usuario
        if SSHManager.upload_file(temp_filename, filename, user_info['numero_economico']):
            # Limpiar archivo temporal
            os.unlink(temp_filename)
            return True
        else:
            st.error("❌ Error subiendo el reporte al servidor")
            # Limpiar archivo temporal en caso de error
            os.unlink(temp_filename)
            return False

    except Exception as e:
        st.error(f"Error guardando el reporte: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return False

def load_existing_reports(user_info):
    """Carga los reportes existentes desde el directorio del usuario en el servidor"""
    try:
        # Listar archivos JSON en el directorio del usuario
        json_files = SSHManager.list_remote_files("*.json", user_info['numero_economico'])

        reports = []
        for filename in json_files:
            # Leer contenido del archivo
            content = SSHManager.get_remote_file(filename, user_info['numero_economico'])
            if content:
                try:
                    report_data = json.loads(content)

                    # Verificar si tiene metadata (para reportes nuevos)
                    # o usar campos antiguos para compatibilidad
                    if 'metadata' not in report_data:
                        # Crear metadata a partir de campos antiguos
                        report_data['metadata'] = {
                            'reportado_por': report_data.get('reportero', {}).get('nombre', ''),
                            'numero_economico': report_data.get('reportado_por', {}).get('numero_economico', ''),
                            'puesto': report_data.get('reportado_por', {}).get('puesto', ''),
                            'fecha_reporte': report_data.get('fecha_reporte', ''),
                            'archivo': filename
                        }

                    report_data['filename'] = filename  # Guardar nombre del archivo
                    reports.append(report_data)
                except json.JSONDecodeError as e:
                    st.warning(f"⚠️ No se pudo decodificar el archivo: {filename}. Error: {str(e)}")
                    continue

        # Ordenar por fecha de reporte, manejando posibles formatos diferentes
        def get_report_date(report):
            fecha_str = report['metadata'].get('fecha_reporte', '')
            try:
                # Intentar parsear diferentes formatos de fecha
                if 'T' in fecha_str:  # Formato ISO
                    # Convertir a datetime sin timezone para comparación
                    dt = datetime.fromisoformat(fecha_str.replace('Z', '+00:00'))
                    return dt.replace(tzinfo=None)  # Remover timezone para comparación
                else:  # Formato string personalizado
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                        try:
                            dt = datetime.strptime(fecha_str, fmt)
                            return dt.replace(tzinfo=None)  # Asegurar datetime naive
                        except ValueError:
                            continue
                # Si no se puede parsear, usar fecha actual (naive)
                return datetime.now().replace(tzinfo=None)
            except:
                # En caso de error, retornar fecha actual (naive)
                return datetime.now().replace(tzinfo=None)

        return sorted(reports, key=get_report_date, reverse=True)

    except Exception as e:
        st.error(f"Error cargando reportes existentes: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return []

def update_report_in_json(updated_data, filename, user_info):
    """Actualiza un reporte existente en formato JSON en el directorio del usuario"""
    try:
        # Añadir información de actualización
        if 'actualizaciones' not in updated_data['metadata']:
            updated_data['metadata']['actualizaciones'] = []

        updated_data['metadata']['actualizaciones'].append({
            'actualizado_por': user_info['nombre'],
            'numero_economico': user_info['numero_economico'],
            'fecha_actualizacion': datetime.now(pytz.timezone('America/Mexico_City')).strftime("%Y-%m-%d %H:%M:%S")
        })

        # Guardar archivo localmente temporalmente
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as tmp_file:
            json.dump(updated_data, tmp_file, ensure_ascii=False, indent=2)
            temp_filename = tmp_file.name

        # Subir al servidor remoto (reemplazar el existente) en el directorio del usuario
        if SSHManager.upload_file(temp_filename, filename, user_info['numero_economico']):
            # Limpiar archivo temporal
            os.unlink(temp_filename)
            return True
        else:
            st.error("❌ Error subiendo el reporte actualizado al servidor")
            # Limpiar archivo temporal en caso de error
            os.unlink(temp_filename)
            return False

    except Exception as e:
        st.error(f"Error actualizando el reporte: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return False

def show_update_form(user_info):
    """Muestra el formulario de actualización de eventos existentes"""
    st.title("🔄 Sistema de Eventos Adversos - Modo Registro")

    # Cargar reportes existentes del usuario
    with st.spinner("Cargando reportes existentes..."):
        reports = load_existing_reports(user_info)

    if not reports:
        st.info("📭 No hay reportes existentes para actualizar")
        return

    # Seleccionar reporte a actualizar
    report_options = []
    for report in reports:
        # Crear descripción para el dropdown
        paciente_nombre = report.get('paciente', {}).get('nombre', 'Nombre no disponible')
        fecha_reporte = report['metadata'].get('fecha_reporte', 'Fecha no disponible')
        # Remover comillas del nombre de archivo para mostrar
        archivo_limpio = report['filename'].replace("'", "")
        descripcion = f"{paciente_nombre} - {fecha_reporte} - {archivo_limpio}"
        report_options.append(descripcion)

    selected_report = st.selectbox(
        "Seleccione el reporte a actualizar:",
        options=report_options,
        index=0
    )

    # Obtener el índice del reporte seleccionado
    selected_index = report_options.index(selected_report)
    original_data = reports[selected_index]
    filename = original_data['filename']

    st.divider()

    # Mostrar información básica del reporte seleccionado
    st.subheader(f"📋 Reporte de: {original_data.get('paciente', {}).get('nombre', 'Nombre no disponible')}")
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Fecha del evento:** {original_data.get('contexto', {}).get('fecha_evento', 'No disponible')}")
        st.info(f"**Ubicación:** {original_data.get('contexto', {}).get('ubicacion', 'No disponible')}")
    with col2:
        st.info(f"**Tipo de evento:** {original_data.get('clasificacion', {}).get('categoria_principal', 'No disponible')}")
        st.info(f"**Reportado por:** {original_data['metadata'].get('reportado_por', 'No disponible')}")

    # Inicializar variables para controlar el estado
    update_submitted = False
    cancel_update = False

    # Mostrar formulario con datos existentes
    with st.form("update_event_form"):
        st.subheader("✏️ Editar información del reporte")

        # Mostrar todas las secciones del formulario con datos existentes
        contexto = show_event_context(original_data)
        clasificacion = show_event_classification(original_data)
        factores = show_contributing_factors(original_data)
        paciente = show_patient_data(original_data)
        clinica = show_clinical_data(original_data)
        descripcion = show_event_description(original_data)
        acciones = show_immediate_actions(original_data)
        seguimiento = show_followup_plan(original_data)
        documentacion = show_documentation(original_data)
        notificaciones = show_notification(original_data)
        certificado_defuncion = show_death_certificate(original_data)

        # Botones dentro del formulario
        col1, col2 = st.columns(2)
        with col1:
            update_submitted = st.form_submit_button("💾 Guardar Cambios", type="primary")
        with col2:
            cancel_update = st.form_submit_button("❌ Cancelar")

    # Manejar las acciones FUERA del formulario
    if cancel_update:
        st.info("Actualización cancelada")
        st.rerun()

    if update_submitted:
        # Validar campos obligatorios
        if not paciente['nombre']:
            st.error("❌ El nombre del paciente es obligatorio")
            return

        if not clasificacion['categoria_principal']:
            st.error("❌ La categoría principal del evento es obligatoria")
            return

        if not descripcion['narrativa']:
            st.error("❌ La descripción narrativa del evento es obligatoria")
            return

        # Crear estructura de datos actualizada
        updated_data = {
            'contexto': contexto,
            'clasificacion': clasificacion,
            'factores': factores,
            'paciente': paciente,
            'clinica': clinica,
            'descripcion': descripcion,
            'acciones': acciones,
            'seguimiento': seguimiento,
            'documentacion': documentacion,
            'notificaciones': notificaciones,
            'certificado_defuncion': certificado_defuncion,
            'metadata': original_data['metadata']  # Mantener metadata original
        }

        # Preservar campos adicionales que puedan existir en el reporte original
        for key in original_data.keys():
            if key not in updated_data and key != 'filename':
                updated_data[key] = original_data[key]

        # Actualizar reporte
        with st.spinner("Guardando cambios..."):
            if update_report_in_json(updated_data, filename, user_info):
                st.success("✅ Reporte actualizado exitosamente!")

                # Mostrar el botón FUERA del formulario
                st.markdown("---")
                if st.button("📝 Continuar editando reportes"):
                    st.rerun()

def show_view_reports(user_info):
    """Muestra la interfaz para visualizar reportes existentes del usuario"""
    st.title("👁️ Visualización de Reportes de Eventos Adversos")

    # Cargar reportes existentes del usuario
    with st.spinner("Cargando reportes existentes..."):
        reports = load_existing_reports(user_info)

    if not reports:
        st.info("📭 No hay reportes existentes para visualizar")
        return

    # Seleccionar reporte a visualizar
    report_options = []
    for report in reports:
        # Crear descripción para el dropdown
        paciente_nombre = report.get('paciente', {}).get('nombre', 'Nombre no disponible')
        fecha_reporte = report['metadata'].get('fecha_reporte', 'Fecha no disponible')
        descripcion = f"{paciente_nombre} - {fecha_reporte} - {report['filename']}"
        report_options.append(descripcion)

    selected_report = st.selectbox(
        "Seleccione el reporte a visualizar:",
        options=report_options,
        index=0
    )

    # Obtener el índice del reporte seleccionado
    selected_index = report_options.index(selected_report)
    report_data = reports[selected_index]

    st.divider()

    # Mostrar información completa del reporte
    st.subheader(f"📋 Reporte Completo: {report_data.get('paciente', {}).get('nombre', 'Nombre no disponible')}")

    # Crear pestañas para organizar la información
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📋 Información General",
        "🏥 Datos Clínicos",
        "⚠️ Evento",
        "🔍 Investigación",
        "📎 Documentación",
        "⚰️ Datos de Defunción",
        "📊 Metadata"
    ])

    with tab1:
        st.header("📋 Información General")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Contexto del Evento")
            if 'contexto' in report_data:
                contexto = report_data['contexto']
                st.write(f"**Fecha del evento:** {contexto.get('fecha_evento', 'No disponible')}")
                st.write(f"**Turno:** {contexto.get('turno', 'No disponible')}")
                st.write(f"**Ubicación:** {contexto.get('ubicacion', 'No disponible')}")
                st.write(f"**Procedimiento asociado:** {contexto.get('procedimiento_asociado', 'No disponible')}")

        with col2:
            st.subheader("Datos del Paciente")
            if 'paciente' in report_data:
                paciente = report_data['paciente']
                st.write(f"**Nombre:** {paciente.get('nombre', 'No disponible')}")
                st.write(f"**Edad:** {paciente.get('edad', 'No disponible')}")
                st.write(f"**Sexo:** {paciente.get('sexo', 'No disponible')}")
                st.write(f"**Expediente:** {paciente.get('expediente', 'No disponible')}")
                st.write(f"**Cama:** {paciente.get('cama', 'No disponible')}")
                st.write(f"**Diagnóstico:** {paciente.get('diagnostico', 'No disponible')}")

    with tab2:
        st.header("🏥 Datos Clínicos")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Signos Vitales")
            if 'clinica' in report_data:
                clinica = report_data['clinica']
                st.write(f"**Tensión Arterial:** {clinica.get('ta', 'No disponible')}")
                st.write(f"**Frecuencia Cardíaca:** {clinica.get('fc', 'No disponible')}")
                st.write(f"**Frecuencia Respiratoria:** {clinica.get('fr', 'No disponible')}")

        with col2:
            st.subheader("Otros Parámetros")
            if 'clinica' in report_data:
                clinica = report_data['clinica']
                st.write(f"**Temperatura:** {clinica.get('temp', 'No disponible')}")
                st.write(f"**SatO₂:** {clinica.get('sato2', 'No disponible')}")
                st.write(f"**Glasgow:** {clinica.get('glasgow', 'No disponible')}")
                st.write(f"**Signos de alerta:** {clinica.get('signos_alerta', 'No disponible')}")

    with tab3:
        st.header("⚠️ Información del Evento")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Clasificación")
            if 'clasificacion' in report_data:
                clasificacion = report_data['clasificacion']
                st.write(f"**Categoría principal:** {clasificacion.get('categoria_principal', 'No disponible')}")
                st.write(f"**Subcategoría:** {clasificacion.get('subcategoria', 'No disponible')}")
                st.write(f"**Gravedad:** {clasificacion.get('gravedad', 'No disponible')}")
                st.write(f"**Detectado en:** {clasificacion.get('detectado_en', 'No disponible')}")

        with col2:
            st.subheader("Factores Contribuyentes")
            if 'factores' in report_data:
                factores = report_data['factores']
                factores_activos = [key for key, value in factores.items() if value]
                if factores_activos:
                    st.write("**Factores identificados:**")
                    for factor in factores_activos:
                        st.write(f"- {factor.replace('_', ' ').title()}")
                else:
                    st.write("No se identificaron factores contribuyentes")

        st.subheader("Descripción del Evento")
        if 'descripcion' in report_data:
            descripcion = report_data['descripcion']
            st.text_area("**Narrativa del evento:**",
                        descripcion.get('narrativa', 'No disponible'),
                        height=150,
                        disabled=True)

            col_desc1, col_desc2 = st.columns(2)
            with col_desc1:
                st.text_area("**Acciones inmediatas:**",
                            descripcion.get('acciones_inmediatas', 'No disponible'),
                            height=100,
                            disabled=True)
            with col_desc2:
                st.text_area("**Resultado para el paciente:**",
                            descripcion.get('resultado_paciente', 'No disponible'),
                            height=100,
                            disabled=True)

    with tab4:
        st.header("🔍 Investigación y Seguimiento")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Acciones Inmediatas")
            if 'acciones' in report_data:
                acciones = report_data['acciones']
                acciones_tomadas = [key for key, value in acciones.items()
                                   if value and key not in ['otras_acciones']]

                if acciones_tomadas:
                    st.write("**Acciones realizadas:**")
                    for accion in acciones_tomadas:
                        st.write(f"- {accion.replace('_', ' ').title()}")

                if acciones.get('otras_acciones'):
                    st.text_area("**Otras acciones:**",
                                acciones.get('otras_acciones'),
                                height=100,
                                disabled=True)

        with col2:
            st.subheader("Plan de Seguimiento")
            if 'seguimiento' in report_data:
                seguimiento = report_data['seguimiento']
                seguimiento_plan = [key for key, value in seguimiento.items()
                                   if value and key not in ['plan_detallado']]

                if seguimiento_plan:
                    st.write("**Seguimiento requerido:**")
                    for item in seguimiento_plan:
                        st.write(f"- {item.replace('_', ' ').title()}")

                if seguimiento.get('plan_detallado'):
                    st.text_area("**Plan detallado:**",
                                seguimiento.get('plan_detallado'),
                                height=100,
                                disabled=True)

    with tab5:
        st.header("📎 Documentación y Notificaciones")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Documentación")
            if 'documentacion' in report_data:
                documentacion = report_data['documentacion']
                if documentacion.get('archivos'):
                    st.write("**Archivos adjuntos:**")
                    for archivo in documentacion.get('archivos', []):
                        st.write(f"- {archivo}")

                if documentacion.get('notas_documentacion'):
                    st.text_area("**Notas de documentación:**",
                                documentacion.get('notas_documentacion'),
                                height=100,
                                disabled=True)

        with col2:
            st.subheader("Notificaciones")
            if 'notificaciones' in report_data:
                notificaciones = report_data['notificaciones']
                notificaciones_realizadas = [key for key, value in notificaciones.items()
                                           if value and key not in ['quien_notifico', 'cuando_notifico']]

                if notificaciones_realizadas:
                    st.write("**Notificaciones realizadas:**")
                    for notif in notificaciones_realizadas:
                        st.write(f"- {notif.replace('_', ' ').title()}")

                st.write(f"**Quién notificó:** {notificaciones.get('quien_notifico', 'No disponible')}")
                st.write(f"**Cuándo notificó:** {notificaciones.get('cuando_notifico', 'No disponible')}")

    with tab6:
        st.header("⚰️ Datos de Defunción")
        if 'certificado_defuncion' in report_data:
            defuncion = report_data['certificado_defuncion']

            if defuncion.get('fallecio', False):
                col1, col2 = st.columns(2)

                with col1:
                    st.write(f"**Falleció:** Sí")
                    if defuncion.get('hora_defuncion'):
                        st.write(f"**Hora de defunción:** {defuncion.get('hora_defuncion', 'No disponible')}")
                    st.write(f"**Folio certificado:** {defuncion.get('folio_certificado', 'No disponible')}")
                    st.write(f"**Causa de muerte:** {defuncion.get('causa_muerte', 'No disponible')}")

                with col2:
                    st.write(f"**Autopsia realizada:** {defuncion.get('autopsia', 'No disponible')}")
                    st.write(f"**Folio obituario:** {defuncion.get('obituario_patologia', 'No disponible')}")
            else:
                st.write("**Falleció:** No")
        else:
            st.write("No hay información de defunción disponible")

    with tab7:
        st.header("📊 Metadata del Reporte")

        if 'metadata' in report_data:
            metadata = report_data['metadata']

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Información de Creación")
                st.write(f"**Reportado por:** {metadata.get('reportado_por', 'No disponible')}")
                st.write(f"**Número económico:** {metadata.get('numero_economico', 'No disponible')}")
                st.write(f"**Puesto:** {metadata.get('puesto', 'No disponible')}")
                st.write(f"**Fecha de reporte:** {metadata.get('fecha_reporte', 'No disponible')}")
                st.write(f"**Archivo:** {metadata.get('archivo', 'No disponible')}")

            with col2:
                st.subheader("Historial de Actualizaciones")
                if 'actualizaciones' in metadata and metadata['actualizaciones']:
                    for i, actualizacion in enumerate(metadata['actualizaciones'], 1):
                        st.write(f"**Actualización {i}:**")
                        st.write(f"- Por: {actualizacion.get('actualizado_por', 'N/A')}")
                        st.write(f"- Número económico: {actualizacion.get('numero_economico', 'N/A')}")
                        st.write(f"- Fecha: {actualizacion.get('fecha_actualizacion', 'N/A')}")
                else:
                    st.write("No hay actualizaciones registradas")

        # Botones para descargar el reporte
        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                label="📥 Descargar Reporte (JSON)",
                data=json.dumps(report_data, indent=2, ensure_ascii=False),
                file_name=report_data['filename'],
                mime="application/json"
            )

        with col2:
            # Botón para generar y descargar PDF
            if st.button("🖨️ Generar PDF", key="generate_pdf_btn"):
                with st.spinner("Generando PDF..."):
                    pdf_bytes = generate_pdf_report(report_data)
                    if pdf_bytes:
                        st.download_button(
                            label="📥 Descargar PDF",
                            data=pdf_bytes,
                            file_name=report_data['filename'].replace('.json', '.pdf'),
                            mime="application/pdf",
                            key="download_pdf_btn"
                        )

    # Botón para regresar a la lista de reportes (SOLO UNO, NO DUPLICADO)
    if st.button("↩️ Volver a la lista de reportes", key="back_to_reports_btn"):
        st.rerun()


# ====================
# FUNCIONES DE AUTENTICACIÓN (CORREGIDAS)
# ====================
def authenticate_user():
    """Autentica al usuario verificando en ambos archivos CSV"""
    st.title("🔐 Sistema de Eventos Adversos - Modo Registro")

    if 'auth_stage' not in st.session_state:
        st.session_state.auth_stage = 'numero_economico'

    if 'numero_economico' not in st.session_state:
        st.session_state.numero_economico = ''

    if st.session_state.auth_stage == 'numero_economico':
        with st.form("auth_form_numero"):
            numero_economico = st.text_input("Número Económico", max_chars=10).strip()
            submitted = st.form_submit_button("Verificar")

            if submitted:
                if not numero_economico:
                    st.error("Por favor ingrese su número económico")
                    return False, None

                st.session_state.numero_economico = numero_economico
                st.info(f"🔍 Verificando número económico: '{numero_economico}'")

                st.info("⏳ Cargando archivo de enfermeras...")
                enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"])

                st.info("⏳ Cargando archivo de claves...")
                claves_df = load_csv_data(CONFIG.FILES["claves"])

                if enfermeras_df is None or claves_df is None:
                    st.error("No se pudieron cargar los archivos necesarios para autenticación")
                    return False, None

                if CONFIG.DEBUG_MODE:
                    st.info("📊 Datos de enfermeras:")
                    st.write(f"Total filas: {len(enfermeras_df)}")
                    st.write("Columnas disponibles:", enfermeras_df.columns.tolist())

                    st.info("🔑 Datos de claves:")
                    st.write(f"Total filas: {len(claves_df)}")
                    st.write("Columnas disponibles:", claves_df.columns.tolist())

                # Verificar columnas requeridas
                required_enfermeras = ['numero_economico', 'puesto', 'nombre_completo']
                for col in required_enfermeras:
                    if col not in enfermeras_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de enfermeras")
                        if CONFIG.DEBUG_MODE:
                            st.write("Columnas disponibles:", enfermeras_df.columns.tolist())
                        return False, None

                required_claves = ['numero_economico', 'password']
                for col in required_claves:
                    if col not in claves_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de claves")
                        if CONFIG.DEBUG_MODE:
                            st.write("Columnas disponibles:", claves_df.columns.tolist())
                        return False, None

                # Limpiar y verificar datos
                enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                numero_clean = numero_economico.strip()

                in_enfermeras = numero_clean in enfermeras_df['numero_economico'].values
                in_claves = numero_clean in claves_df['numero_economico'].values

                if not in_enfermeras or not in_claves:
                    st.error("❌ Número económico no registrado o sin permisos")
                    return False, None

                # Obtener datos del usuario
                user_data = enfermeras_df[enfermeras_df['numero_economico'] == numero_clean].iloc[0]
                puesto = user_data['puesto'].strip().lower()

                # Verificar permisos - SOLO permitir supervisión turno y jefatura servicio
                puestos_permitidos = ['supervision turno', 'jefatura servicio']
                if puesto not in puestos_permitidos and not CONFIG.SUPERVISOR_MODE:
                    st.error("❌ Su puesto no tiene permisos para acceder a esta aplicación")
                    st.info(f"Puestos permitidos: {', '.join(puestos_permitidos)}")
                    return False, None

                st.session_state.auth_stage = 'password'
                st.session_state.user_data = {
                    'numero_economico': numero_clean,
                    'nombre_completo': user_data['nombre_completo'],
                    'puesto': puesto
                }
                st.rerun()

    elif st.session_state.auth_stage == 'password':
        with st.form("auth_form_password"):
            st.info(f"Verificando usuario: {st.session_state.user_data['nombre_completo']}")
            password = st.text_input("Contraseña", type="password")
            confirm = st.form_submit_button("Validar Contraseña")

            if confirm:
                if not password:
                    st.error("❌ Por favor ingrese su contraseña")
                    return False, None

                claves_df = load_csv_data(CONFIG.FILES["claves"])
                if claves_df is None:
                    st.error("No se pudo cargar el archivo de claves")
                    return False, None

                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                user_clave = claves_df[claves_df['numero_economico'] == st.session_state.numero_economico].iloc[0]

                if user_clave['password'] != password:
                    st.error("❌ Contraseña incorrecta")
                    return False, None

                st.success("✅ Autenticación exitosa")
                st.session_state.auth_stage = 'authenticated'
                st.rerun()

    elif st.session_state.auth_stage == 'authenticated':
        return True, {
            'numero_economico': st.session_state.numero_economico,
            'nombre': st.session_state.user_data['nombre_completo'],
            'puesto': st.session_state.user_data['puesto']
        }

    return False, None

# ====================
# SECCIONES DEL CUESTIONARIO
# ====================
def show_event_context(report_data=None):
    """Muestra la sección de contexto del evento"""
    with st.expander("📌 Contexto del Evento", expanded=True):
        # Obtener valores por defecto si estamos en modo edición
        default_fecha = datetime.today()
        default_turno = ""
        default_ubicacion = ""
        default_procedimiento = ""
        
        if report_data and 'contexto' in report_data:
            contexto = report_data['contexto']
            if 'fecha_evento' in contexto:
                try:
                    default_fecha = datetime.strptime(contexto['fecha_evento'], "%Y-%m-%d")
                except:
                    default_fecha = datetime.today()
            default_turno = contexto.get('turno', '')
            default_ubicacion = contexto.get('ubicacion', '')
            default_procedimiento = contexto.get('procedimiento_asociado', '')
        
        col1, col2 = st.columns(2)
        with col1:
            fecha_evento = st.date_input("📅 Fecha del evento", default_fecha)
            turno = st.selectbox("🕒 Turno", [
                "Matutino (7:00-15:00)", 
                "Vespertino (14:30-21:00)", 
                "Nocturno (A y B) (20:30-8:00)",
                "Jornada Acumulada (8:00-20:00)"
            ], index=get_index([
                "Matutino (7:00-15:00)", 
                "Vespertino (14:30-21:00)", 
                "Nocturno (A y B) (20:30-8:00)",
                "Jornada Acumulada (8:00-20:00)"
            ], default_turno))
        with col2:
            ubicacion = st.selectbox("🏥 Servicio donde ocurrió", [
                "Dirección-Enfermería",
                "Consulta-Externa",
                "Diagnóstico",
                "CEyE-Hospitalización",
                "Unidad-Coronaria",
                "Hemodinámica",
                "3-piso",
                "Cardio-Neumología",
                "Nefrología",
                "CeyE-Quirúrgica",
                "SOP",
                "Perfusión",
                "TIC",
                "6-Piso",
                "7-Piso",
                "8-Piso",
                "9-Piso"
            ], index=get_index([
                "Dirección-Enfermería",
                "Consulta-Externa",
                "Diagnóstico",
                "CEyE-Hospitalización",
                "Unidad-Coronaria",
                "Hemodinámica",
                "3-piso",
                "Cardio-Neumología",
                "Nefrología",
                "CeyE-Quirúrgica",
                "SOP",
                "Perfusión",
                "TIC",
                "6-Piso",
                "7-Piso",
                "8-Piso",
                "9-Piso"
            ], default_ubicacion))
            procedimiento_asociado = st.selectbox("🩺 Procedimiento relacionado (si aplica)", [
                "",
                "Cateterismo Cardiaco",
                "Angioplastia/Stent",
                "Ablación",
                "Implante de Marcapasos/DAI",
                "Cirugía de Bypass",
                "Valvuloplastía",
                "ECMO",
                "Otro"
            ], index=get_index([
                "",
                "Cateterismo Cardiaco",
                "Angioplastia/Stent",
                "Ablación",
                "Implante de Marcapasos/DAI",
                "Cirugía de Bypass",
                "Valvuloplastía",
                "ECMO",
                "Otro"
            ], default_procedimiento))
    return {
        "fecha_evento": fecha_evento.strftime("%Y-%m-%d"),
        "turno": turno,
        "ubicacion": ubicacion,
        "procedimiento_asociado": procedimiento_asociado
    }

def show_event_classification(report_data=None):
    """Muestra la clasificación del evento grave o adverso"""
    with st.expander("⚠️ Clasificación del Evento Grave o Adverso", expanded=True):
        # Obtener valores por defecto si estamos en modo edición
        default_categoria = ""
        default_subcategoria = ""
        default_gravedad = ""
        default_detectado = ""
        
        if report_data and 'clasificacion' in report_data:
            clasificacion = report_data['clasificacion']
            default_categoria = clasificacion.get('categoria_principal', '')
            default_subcategoria = clasificacion.get('subcategoria', '')
            default_gravedad = clasificacion.get('gravedad', '')
            default_detectado = clasificacion.get('detectado_en', '')
        
        categoria_principal = st.selectbox("🔍 Tipo principal de evento", [
            "",
            "Evento adverso (EA)",
            "Evento centinela",  
            "Cuasi evento/incidente sin daño"
        ], index=get_index([
            "",
            "Evento adverso (EA)",
            "Evento centinela",  
            "Cuasi evento/incidente sin daño"
        ], default_categoria))

        subcategorias = {
            "Evento adverso (EA)": [
                "Complicación Isquémica",
                "Arritmia",
                "Complicación Hemodinámica",
                "Complicación Vascular",
                "Evento Tromboembólico",
                "Reacción a Medios de Contraste",
                "Infección Asociada",
                "Falla de Equipo Crítico",
                "Error en Medicación Cardiovascular"
            ],
            "Evento centinela": [
                "Muerte inesperada",
                "Discapacidad permanente",
                "Intervención quirúrgica no planeada",
                "Retención de objeto extraño"
            ],
            "Cuasi evento/incidente sin daño": [
                "Error detectado a tiempo",
                "Falla de equipo sin consecuencias",
                "Error de medicación sin daño"
            ]
        }

        subcategoria = ""
        if categoria_principal in subcategorias:
            subcat_options = [""] + subcategorias[categoria_principal]
            subcategoria = st.selectbox("📌 Subcategoría específica", subcat_options, 
                                      index=get_index(subcat_options, default_subcategoria))

        col1, col2 = st.columns(2)
        with col1:
            gravedad_opciones = [
                "Leve (sin daño al paciente)",
                "Moderado (daño temporal)",
                "Grave (daño permanente)",
                "Crítico (muerte o riesgo vital)"
            ]
            gravedad = st.radio("📊 Gravedad del Evento", gravedad_opciones,
                              index=get_index(gravedad_opciones, default_gravedad))
        with col2:
            detectado_opciones = [
                "Antes del procedimiento",
                "Durante el procedimiento",
                "Inmediatamente después",
                "Tardíamente (fuera de área crítica)"
            ]
            detectado_en = st.radio("🔎 ¿Cuándo se detectó?", detectado_opciones,
                                  index=get_index(detectado_opciones, default_detectado))
    
    return {
        "categoria_principal": categoria_principal,
        "subcategoria": subcategoria,
        "gravedad": gravedad,
        "detectado_en": detectado_en
    }

def show_contributing_factors(report_data=None):
    """Muestra los factores contribuyentes"""
    with st.expander("🔎 Factores Contribuyentes", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_factores = {}
        if report_data and 'factores' in report_data:
            default_factores = report_data['factores']
        
        cols = st.columns(3)
        factores = {}
        with cols[0]:
            st.markdown("**Factores del Paciente**")
            factores["condicion_base"] = st.checkbox("Condición de base del paciente", 
                                                   value=default_factores.get('condicion_base', False))
            factores["comorbilidades"] = st.checkbox("Comorbilidades", 
                                                   value=default_factores.get('comorbilidades', False))
            factores["alergias"] = st.checkbox("Alergias no identificadas", 
                                             value=default_factores.get('alergias', False))
        
        with cols[1]:
            st.markdown("**Factores Técnicos**")
            factores["equipo"] = st.checkbox("Falla de equipo", 
                                           value=default_factores.get('equipo', False))
            factores["medicamento"] = st.checkbox("Problema con medicamento", 
                                                value=default_factores.get('medicamento', False))
            factores["procedimiento"] = st.checkbox("Dificultad en procedimiento", 
                                                  value=default_factores.get('procedimiento', False))
        
        with cols[2]:
            st.markdown("**Factores Humanos**")
            factores["comunicacion"] = st.checkbox("Falla en comunicación", 
                                                 value=default_factores.get('comunicacion', False))
            factores["fatiga"] = st.checkbox("Fatiga del personal", 
                                           value=default_factores.get('fatiga', False))
            factores["entrenamiento"] = st.checkbox("Falta de entrenamiento", 
                                                  value=default_factores.get('entrenamiento', False))
    
    return factores

def show_patient_data(report_data=None):
    """Muestra los datos del paciente"""
    with st.expander("👨‍⚕️ Datos del Paciente", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_paciente = {}
        if report_data and 'paciente' in report_data:
            default_paciente = report_data['paciente']
        
        cols = st.columns(2)
        paciente_data = {}
        with cols[0]:
            paciente_data["nombre"] = st.text_input("Nombre completo del paciente", 
                                                  value=default_paciente.get('nombre', ''))
            paciente_data["edad"] = st.number_input("Edad", min_value=0, max_value=120, 
                                                  value=int(default_paciente.get('edad', 30)) if default_paciente.get('edad') else 30)
            sexo_opciones = ["Masculino", "Femenino", "Otro"]
            paciente_data["sexo"] = st.selectbox("Sexo", sexo_opciones,
                                               index=get_index(sexo_opciones, default_paciente.get('sexo', '')))
        with cols[1]:
            paciente_data["expediente"] = st.text_input("Número de expediente", 
                                                      value=default_paciente.get('expediente', ''))
            paciente_data["cama"] = st.text_input("Número de cama", 
                                                value=default_paciente.get('cama', ''))
            paciente_data["diagnostico"] = st.text_input("Diagnóstico principal", 
                                                       value=default_paciente.get('diagnostico', ''))
    return paciente_data

def show_event_description(report_data=None):
    """Muestra la descripción narrativa del evento"""
    with st.expander("📝 Descripción Narrativa del Evento", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_descripcion = {}
        if report_data and 'descripcion' in report_data:
            default_descripcion = report_data['descripcion']
        
        descripcion = {}
        descripcion["narrativa"] = st.text_area(
            "Describa detalladamente el evento, incluyendo:\n"
            "- Qué sucedió exactamente\n"
            "- Quiénes estuvieron involucrados\n"
            "- Secuencia de eventos\n"
            "- Acciones tomadas inmediatamente\n"
            "- Respuesta del paciente",
            height=150,
            value=default_descripcion.get('narrativa', '')
        )
        
        cols = st.columns(2)
        with cols[0]:
            descripcion["acciones_inmediatas"] = st.text_area(
                "Acciones tomadas inmediatamente",
                height=100,
                value=default_descripcion.get('acciones_inmediatas', '')
            )
        with cols[1]:
            descripcion["resultado_paciente"] = st.text_area(
                "Resultado para el paciente",
                height=100,
                value=default_descripcion.get('resultado_paciente', '')
            )
    
    return descripcion

def generate_pdf_report(report_data):
    """Genera un PDF completo del reporte de evento adverso con todos los campos"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        from io import BytesIO

        # Crear buffer para el PDF
        buffer = BytesIO()

        # Configurar documento
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)

        # Estilos
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER))
        styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
        styles.add(ParagraphStyle(name='Small', parent=styles['BodyText'], fontSize=8))

        # Elementos del documento
        elements = []

        # Título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        elements.append(Paragraph("REPORTE COMPLETO DE EVENTO ADVERSO", title_style))
        elements.append(Spacer(1, 12))

        # ===== INFORMACIÓN BÁSICA =====
        elements.append(Paragraph("INFORMACIÓN BÁSICA", styles['Heading2']))

        basic_data = [
            ["Paciente:", report_data.get('paciente', {}).get('nombre', 'N/A')],
            ["Fecha del evento:", report_data.get('contexto', {}).get('fecha_evento', 'N/A')],
            ["Turno:", report_data.get('contexto', {}).get('turno', 'N/A')],
            ["Ubicación:", report_data.get('contexto', {}).get('ubicacion', 'N/A')],
            ["Procedimiento:", report_data.get('contexto', {}).get('procedimiento_asociado', 'N/A')],
            ["Tipo de evento:", report_data.get('clasificacion', {}).get('categoria_principal', 'N/A')],
            ["Subcategoría:", report_data.get('clasificacion', {}).get('subcategoria', 'N/A')],
            ["Gravedad:", report_data.get('clasificacion', {}).get('gravedad', 'N/A')],
            ["Detectado en:", report_data.get('clasificacion', {}).get('detectado_en', 'N/A')]
        ]

        basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        elements.append(basic_table)
        elements.append(Spacer(1, 12))

        # ===== DATOS DEL PACIENTE =====
        elements.append(Paragraph("DATOS DEL PACIENTE", styles['Heading2']))

        patient_data = [
            ["Edad:", str(report_data.get('paciente', {}).get('edad', 'N/A'))],
            ["Sexo:", report_data.get('paciente', {}).get('sexo', 'N/A')],
            ["Expediente:", report_data.get('paciente', {}).get('expediente', 'N/A')],
            ["Cama:", report_data.get('paciente', {}).get('cama', 'N/A')],
            ["Diagnóstico:", report_data.get('paciente', {}).get('diagnostico', 'N/A')]
        ]

        patient_table = Table(patient_data, colWidths=[1.5*inch, 4.5*inch])
        patient_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        elements.append(patient_table)
        elements.append(Spacer(1, 12))

        # ===== DATOS CLÍNICOS =====
        elements.append(Paragraph("DATOS CLÍNICOS", styles['Heading2']))

        clinical_data = [
            ["Tensión Arterial:", report_data.get('clinica', {}).get('ta', 'N/A')],
            ["Frecuencia Cardíaca:", report_data.get('clinica', {}).get('fc', 'N/A')],
            ["Frecuencia Respiratoria:", report_data.get('clinica', {}).get('fr', 'N/A')],
            ["Temperatura:", report_data.get('clinica', {}).get('temp', 'N/A')],
            ["SatO₂:", report_data.get('clinica', {}).get('sato2', 'N/A')],
            ["Escala de Glasgow:", report_data.get('clinica', {}).get('glasgow', 'N/A')],
            ["Signos de alerta:", report_data.get('clinica', {}).get('signos_alerta', 'N/A')]
        ]

        clinical_table = Table(clinical_data, colWidths=[2*inch, 4*inch])
        clinical_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        elements.append(clinical_table)
        elements.append(Spacer(1, 12))

        # ===== FACTORES CONTRIBUYENTES =====
        elements.append(Paragraph("FACTORES CONTRIBUYENTES", styles['Heading2']))

        factores = report_data.get('factores', {})
        factores_list = []
        for factor, valor in factores.items():
            if valor and factor not in ['otras_acciones', 'plan_detallado']:
                factores_list.append([factor.replace('_', ' ').title(), "✓"])

        if factores_list:
            factores_table = Table(factores_list, colWidths=[3*inch, 1*inch])
            factores_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(factores_table)
        else:
            elements.append(Paragraph("No se identificaron factores contribuyentes", styles['BodyText']))
        
        elements.append(Spacer(1, 12))

        # ===== DESCRIPCIÓN DEL EVENTO =====
        elements.append(Paragraph("DESCRIPCIÓN DEL EVENTO", styles['Heading2']))
        elements.append(Paragraph("Narrativa del evento:", styles['Heading3']))
        elements.append(Paragraph(report_data.get('descripcion', {}).get('narrativa', 'No disponible'), styles['BodyText']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Acciones inmediatas:", styles['Heading3']))
        elements.append(Paragraph(report_data.get('descripcion', {}).get('acciones_inmediatas', 'No disponible'), styles['BodyText']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Resultado para el paciente:", styles['Heading3']))
        elements.append(Paragraph(report_data.get('descripcion', {}).get('resultado_paciente', 'No disponible'), styles['BodyText']))
        elements.append(Spacer(1, 12))

        # ===== ACCIONES INMEDIATAS =====
        elements.append(Paragraph("ACCIONES INMEDIATAS TOMADAS", styles['Heading2']))

        acciones = report_data.get('acciones', {})
        acciones_list = []
        for accion, valor in acciones.items():
            if valor and accion not in ['otras_acciones']:
                acciones_list.append([accion.replace('_', ' ').title(), "✓"])

        if acciones_list:
            acciones_table = Table(acciones_list, colWidths=[3*inch, 1*inch])
            acciones_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(acciones_table)

        if acciones.get('otras_acciones'):
            elements.append(Paragraph("Otras acciones:", styles['Heading3']))
            elements.append(Paragraph(acciones.get('otras_acciones'), styles['BodyText']))
        
        elements.append(Spacer(1, 12))

        # ===== PLAN DE SEGUIMIENTO =====
        elements.append(Paragraph("PLAN DE SEGUIMIENTO", styles['Heading2']))

        seguimiento = report_data.get('seguimiento', {})
        seguimiento_list = []
        for item, valor in seguimiento.items():
            if valor and item not in ['plan_detallado']:
                seguimiento_list.append([item.replace('_', ' ').title(), "✓"])

        if seguimiento_list:
            seguimiento_table = Table(seguimiento_list, colWidths=[3*inch, 1*inch])
            seguimiento_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(seguimiento_table)

        if seguimiento.get('plan_detallado'):
            elements.append(Paragraph("Plan detallado:", styles['Heading3']))
            elements.append(Paragraph(seguimiento.get('plan_detallado'), styles['BodyText']))
        
        elements.append(Spacer(1, 12))

        # ===== NOTIFICACIONES =====
        elements.append(Paragraph("NOTIFICACIONES REALIZADAS", styles['Heading2']))

        notificaciones = report_data.get('notificaciones', {})
        notificaciones_list = []
        for notif, valor in notificaciones.items():
            if valor and notif not in ['quien_notifico', 'cuando_notifico']:
                notificaciones_list.append([notif.replace('_', ' ').title(), "✓"])

        if notificaciones_list:
            notificaciones_table = Table(notificaciones_list, colWidths=[3*inch, 1*inch])
            notificaciones_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(notificaciones_table)

        elements.append(Paragraph(f"Quién notificó: {notificaciones.get('quien_notifico', 'N/A')}", styles['BodyText']))
        elements.append(Paragraph(f"Cuándo notificó: {notificaciones.get('cuando_notifico', 'N/A')}", styles['BodyText']))
        elements.append(Spacer(1, 12))

        # ===== DATOS DE DEFUNCIÓN =====
        certificado = report_data.get('certificado_defuncion', {})
        if certificado.get('fallecio', False):
            elements.append(Paragraph("DATOS DE DEFUNCIÓN", styles['Heading2']))
            
            defuncion_data = [
                ["Hora de defunción:", certificado.get('hora_defuncion', 'N/A')],
                ["Folio certificado:", certificado.get('folio_certificado', 'N/A')],
                ["Causa de muerte:", certificado.get('causa_muerte', 'N/A')],
                ["Autopsia realizada:", certificado.get('autopsia', 'N/A')],
                ["Folio obituario:", certificado.get('obituario_patologia', 'N/A')]
            ]
            
            defuncion_table = Table(defuncion_data, colWidths=[2*inch, 4*inch])
            defuncion_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            elements.append(defuncion_table)
            elements.append(Spacer(1, 12))

        # ===== INFORMACIÓN DEL REPORTE =====
        elements.append(Paragraph("INFORMACIÓN DEL REPORTE", styles['Heading2']))

        if 'metadata' in report_data:
            metadata = report_data['metadata']
            report_info = [
                ["Reportado por:", metadata.get('reportado_por', 'N/A')],
                ["Número económico:", metadata.get('numero_economico', 'N/A')],
                ["Puesto:", metadata.get('puesto', 'N/A')],
                ["Fecha de reporte:", metadata.get('fecha_reporte', 'N/A')],
                ["Archivo:", metadata.get('archivo', 'N/A')],
                ["Servicio:", metadata.get('servicio', 'N/A')],
                ["Turno laboral:", metadata.get('turno_laboral', 'N/A')]
            ]

            report_table = Table(report_info, colWidths=[2*inch, 4*inch])
            report_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))

            elements.append(report_table)

            # Historial de actualizaciones
            if 'actualizaciones' in metadata and metadata['actualizaciones']:
                elements.append(Spacer(1, 12))
                elements.append(Paragraph("HISTORIAL DE ACTUALIZACIONES", styles['Heading3']))
                
                for i, actualizacion in enumerate(metadata['actualizaciones'], 1):
                    elements.append(Paragraph(f"Actualización {i}:", styles['Heading4']))
                    elements.append(Paragraph(f"Por: {actualizacion.get('actualizado_por', 'N/A')}", styles['BodyText']))
                    elements.append(Paragraph(f"Número económico: {actualizacion.get('numero_economico', 'N/A')}", styles['BodyText']))
                    elements.append(Paragraph(f"Fecha: {actualizacion.get('fecha_actualizacion', 'N/A')}", styles['BodyText']))
                    elements.append(Spacer(1, 6))

        # Generar PDF
        doc.build(elements)

        # Obtener bytes del PDF
        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    except Exception as e:
        st.error(f"Error generando PDF: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return None

def show_immediate_actions(report_data=None):
    """Muestra las acciones inmediatas tomadas"""
    with st.expander("⚡ Acciones Inmediatas Tomadas", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_acciones = {}
        if report_data and 'acciones' in report_data:
            default_acciones = report_data['acciones']

        acciones = {}

        cols = st.columns(2)
        with cols[0]:
            acciones["notificacion_medico"] = st.checkbox(
                "Médico notificado inmediatamente",
                value=default_acciones.get('notificacion_medico', False)
            )
            acciones["monitoreo_intensivo"] = st.checkbox(
                "Monitoreo intensificado",
                value=default_acciones.get('monitoreo_intensivo', False)
            )
            acciones["medicamento_administrado"] = st.checkbox(
                "Medicamento de emergencia administrado",
                value=default_acciones.get('medicamento_administrado', False)
            )
        with cols[1]:
            acciones["equipo_revisado"] = st.checkbox(
                "Equipo revisado/reemplazado",
                value=default_acciones.get('equipo_revisado', False)
            )
            acciones["protocolo_activado"] = st.checkbox(
                "Protocolo de emergencia activado",
                value=default_acciones.get('protocolo_activado', False)
            )
            acciones["familia_notificada"] = st.checkbox(
                "Familia notificada",
                value=default_acciones.get('familia_notificada', False)
            )

        acciones["otras_acciones"] = st.text_area(
            "Otras acciones tomadas",
            value=default_acciones.get('otras_acciones', '')
        )

    return acciones

def get_index(options, value):
    """Obtiene el índice de un valor en una lista de opciones"""
    if not value:
        return 0
    try:
        return options.index(value)
    except ValueError:
        return 0

def show_clinical_data(report_data=None):
    """Muestra datos clínicos relevantes"""
    with st.expander("🏥 Datos Clínicos Relevantes", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_clinica = {}
        if report_data and 'clinica' in report_data:
            default_clinica = report_data['clinica']
        
        clinica = {}
        
        cols = st.columns(2)
        with cols[0]:
            ta_opciones = [
                "",
                "<90/60 (Hipotensión)",
                "90/60-120/80 (Normal)",
                "121/81-139/89 (Elevada)",
                "140/90-159/99 (HTN Grado 1)",
                "≥160/100 (HTN Grado 2)",
                "Otro"
            ]
            clinica["ta"] = st.selectbox("Tensión Arterial (mmHg)", ta_opciones,
                                       index=get_index(ta_opciones, default_clinica.get('ta', '')))
            
            fc_opciones = [
                "",
                "<60 (Bradicardia)",
                "60-100 (Normal)",
                ">100 (Taquicardia)",
                "Otro"
            ]
            clinica["fc"] = st.selectbox("Frecuencia Cardíaca (lpm)", fc_opciones,
                                       index=get_index(fc_opciones, default_clinica.get('fc', '')))
            
            fr_opciones = [
                "",
                "<12 (Bradipnea)",
                "12-20 (Normal)",
                ">20 (Taquipnea)",
                "Otro"
            ]
            clinica["fr"] = st.selectbox("Frecuencia Respiratoria (rpm)", fr_opciones,
                                       index=get_index(fr_opciones, default_clinica.get('fr', '')))
        
        with cols[1]:
            temp_opciones = [
                "",
                "<36 (Hipotermia)",
                "36-37.2 (Normal)",
                "37.3-38 (Febrícula)",
                ">38 (Fiebre)",
                "Otro"
            ]
            clinica["temp"] = st.selectbox("Temperatura (°C)", temp_opciones,
                                         index=get_index(temp_opciones, default_clinica.get('temp', '')))
            
            sato2_opciones = [
                "",
                "<90% (Hipoxemia)",
                "90-94% (Limitrofe)",
                "≥95% (Normal)",
                "Otro"
            ]
            clinica["sato2"] = st.selectbox("SatO₂ (%)", sato2_opciones,
                                          index=get_index(sato2_opciones, default_clinica.get('sato2', '')))
            
            glasgow_opciones = [
                "",
                "3-8 (Grave)",
                "9-12 (Moderado)",
                "13-15 (Leve)",
                "Otro"
            ]
            clinica["glasgow"] = st.selectbox("Escala de Glasgow", glasgow_opciones,
                                            index=get_index(glasgow_opciones, default_clinica.get('glasgow', '')))
        
        clinica["signos_alerta"] = st.text_area("Signos de alerta presentes",
                                              value=default_clinica.get('signos_alerta', ''))
    
    return clinica

def show_followup_plan(report_data=None):
    """Muestra el plan de seguimiento"""
    with st.expander("📋 Plan de Seguimiento", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_seguimiento = {}
        if report_data and 'seguimiento' in report_data:
            default_seguimiento = report_data['seguimiento']
        
        seguimiento = {}
        
        cols = st.columns(2)
        with cols[0]:
            seguimiento["monitoreo_continuo"] = st.checkbox(
                "Monitoreo continuo requerido",
                value=default_seguimiento.get('monitoreo_continuo', False)
            )
            seguimiento["consulta_especialista"] = st.checkbox(
                "Consulta a especialista requerida",
                value=default_seguimiento.get('consulta_especialista', False)
            )
            seguimiento["pruebas_adicionales"] = st.checkbox(
                "Pruebas adicionales necesarias",
                value=default_seguimiento.get('pruebas_adicionales', False)
            )
        with cols[1]:
            seguimiento["cambio_medicamento"] = st.checkbox(
                "Cambio en medicación requerido",
                value=default_seguimiento.get('cambio_medicamento', False)
            )
            seguimiento["transferencia_uci"] = st.checkbox(
                "Transferencia a UCI requerida",
                value=default_seguimiento.get('transferencia_uci', False)
            )
            seguimiento["evaluacion_riesgos"] = st.checkbox(
                "Evaluación de riesgos adicional",
                value=default_seguimiento.get('evaluacion_riesgos', False)
            )
        
        seguimiento["plan_detallado"] = st.text_area(
            "Plan de seguimiento detallado",
            value=default_seguimiento.get('plan_detallado', '')
        )
    
    return seguimiento

def show_logo():
    """Muestra el logo en la parte superior de forma simple y efectiva"""
    try:
        # Intentar diferentes rutas posibles
        possible_paths = [
            "escudo_COLOR.jpg",
            "./escudo_COLOR.jpg",
            "images/escudo_COLOR.jpg",
            "./images/escudo_COLOR.jpg"
        ]

        logo_found = False
        for logo_path in possible_paths:
            try:
                # Usar el mismo approach que en el programa que funciona
                st.image(logo_path, width=150)
                logo_found = True
                if CONFIG.DEBUG_MODE:
                    st.success(f"✅ Logo cargado desde: {logo_path}")
                break
            except:
                continue

        if not logo_found:
            # Fallback: mostrar título
            st.markdown(
                '<div style="text-align: center;"><h2>🏥 Supervisión de Enfermería por Turno</h2></div>',
                unsafe_allow_html=True
            )
            if CONFIG.DEBUG_MODE:
                st.warning("⚠️ Logo no encontrado en las rutas habituales")

    except Exception as e:
        # Fallback en caso de error
        st.markdown(
            '<div style="text-align: center;"><h2>🏥 Supervisión de Enfermería por Turno</h2></div>',
            unsafe_allow_html=True
        )
        if CONFIG.DEBUG_MODE:
            st.error(f"Error cargando logo: {str(e)}")

def show_documentation(report_data=None):
    """Muestra la sección de documentación y evidencias"""
    with st.expander("📎 Documentación y Evidencias", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_docs = {}
        if report_data and 'documentacion' in report_data:
            default_docs = report_data['documentacion']
        
        documentacion = {}
        
        # Archivos subidos previamente (solo nombres para mostrar)
        archivos_subidos = default_docs.get('archivos', [])
        if archivos_subidos:
            st.info("📄 Archivos ya subidos:")
            for archivo in archivos_subidos:
                st.write(f"- {archivo}")
        
        uploaded_files = st.file_uploader(
            "Subir evidencias (fotos, registros, etc.)",
            type=['jpg', 'jpeg', 'png', 'pdf', 'txt'],
            accept_multiple_files=True
        )
        
        documentacion['archivos'] = uploaded_files
        documentacion['notas_documentacion'] = st.text_area(
            "Notas adicionales sobre documentación",
            value=default_docs.get('notas_documentacion', '')
        )
    
    return documentacion

def show_notification(report_data=None):
    """Muestra la sección de notificaciones"""
    with st.expander("📞 Notificaciones Realizadas", expanded=False):
        # Obtener valores por defecto si estamos en modo edición
        default_notificaciones = {}
        if report_data and 'notificaciones' in report_data:
            default_notificaciones = report_data['notificaciones']
        
        notificaciones = {}
        
        cols = st.columns(2)
        with cols[0]:
            notificaciones["jefe_servicio"] = st.checkbox(
                "Jefe de servicio notificado",
                value=default_notificaciones.get('jefe_servicio', False)
            )
            notificaciones["calidad"] = st.checkbox(
                "Departamento de calidad notificado",
                value=default_notificaciones.get('calidad', False)
            )
        with cols[1]:
            notificaciones["riesgos"] = st.checkbox(
                "Departamento de riesgos notificado",
                value=default_notificaciones.get('riesgos', False)
            )
            notificaciones["administracion"] = st.checkbox(
                "Administración notificada",
                value=default_notificaciones.get('administracion', False)
            )
        
        notificaciones["quien_notifico"] = st.text_input(
            "Persona que realizó la notificación",
            value=default_notificaciones.get('quien_notifico', '')
        )
        notificaciones["cuando_notifico"] = st.text_input(
            "Fecha y hora de notificación",
            value=default_notificaciones.get('cuando_notifico', '')
        )
    
    return notificaciones

def show_death_certificate(report_data=None):
    """Muestra la sección de certificado de defunción usando pestañas"""
    with st.expander("⚰️ Datos de Defunción (si aplica)", expanded=False):
        death_data = {}

        # Obtener valores por defecto si estamos en modo edición
        default_fallecio = False
        default_hora = ""
        default_folio = ""
        default_causa = ""
        default_autopsia = "No"
        default_obituario = ""

        if report_data and 'certificado_defuncion' in report_data:
            default_data = report_data['certificado_defuncion']
            default_fallecio = default_data.get('fallecio', False)

            # Convertir hora a string si existe
            if default_data.get('hora_defuncion'):
                if isinstance(default_data['hora_defuncion'], time):
                    default_hora = default_data['hora_defuncion'].strftime('%H:%M:%S')
                else:
                    default_hora = str(default_data['hora_defuncion'])

            default_folio = default_data.get('folio_certificado', '')
            default_causa = default_data.get('causa_muerte', '')
            default_autopsia = default_data.get('autopsia', 'No')
            default_obituario = default_data.get('obituario_patologia', '')

        # Usar pestañas en lugar de radio buttons
        tab_no, tab_si = st.tabs(["❌ No falleció", "✅ Sí falleció"])

        with tab_no:
            st.info("El paciente no falleció durante el evento")
            death_data["fallecio"] = False
            # Establecer valores vacíos para cuando no falleció
            death_data["hora_defuncion"] = ""
            death_data["folio_certificado"] = ""
            death_data["causa_muerte"] = ""
            death_data["autopsia"] = "No"
            death_data["obituario_patologia"] = ""

        with tab_si:
            st.success("Complete los datos de defunción:")
            death_data["fallecio"] = True

            cols = st.columns(3)

            with cols[0]:
                # Obtener hora como objeto time pero convertir a string inmediatamente
                hora_time = st.time_input("Hora de defunción",
                                        value=datetime.strptime(default_hora, '%H:%M:%S').time() if default_hora and default_hora != "" else time(0, 0))
                death_data["hora_defuncion"] = hora_time.strftime('%H:%M:%S')  # Convertir a string

            with cols[1]:
                death_data["folio_certificado"] = st.text_input(
                    "Número de folio del certificado médico *",
                    value=default_folio,
                    key="folio_certificado"
                )
                death_data["causa_muerte"] = st.selectbox(
                    "Causa principal de muerte *",
                    [
                        "",
                        "Infarto agudo de miocardio",
                        "Choque cardiogénico",
                        "Arritmia fatal",
                        "Taponamiento cardíaco",
                        "Embolia pulmonar masiva",
                        "Accidente cerebrovascular",
                        "Sepsis",
                        "Otra causa cardiovascular",
                        "Causa no cardiovascular"
                    ],
                    index=get_index([
                        "",
                        "Infarto agudo de miocardio",
                        "Choque cardiogénico",
                        "Arritmia fatal",
                        "Taponamiento cardíaco",
                        "Embolia pulmonar masiva",
                        "Accidente cerebrovascular",
                        "Sepsis",
                        "Otra causa cardiovascular",
                        "Causa no cardiovascular"
                    ], default_causa),
                    key="causa_muerte"
                )

            with cols[2]:
                death_data["autopsia"] = st.radio(
                    "¿Se realizó autopsia?",
                    ["No", "Sí"],
                    horizontal=True,
                    index=1 if default_autopsia == "Sí" else 0,
                    key="autopsia"
                )
                death_data["obituario_patologia"] = st.text_input(
                    "Folio obituario (Patología)",
                    value=default_obituario,
                    key="obituario"
                )

            # Validación de campos obligatorios
            if death_data["folio_certificado"].strip() == "":
                st.warning("⚠️ El número de folio del certificado médico es obligatorio, si aún no lo tiene escriba 00000")
            if death_data["causa_muerte"].strip() == "":
                st.warning("⚠️ La causa principal de muerte es obligatoria")

    return death_data

# ====================
# FUNCIONES DE CORREO
# ====================
def send_email_notification(report_data, user_info):
    """Envía notificación por email del reporte"""
    try:
        # Configurar el mensaje
        msg = MIMEMultipart()
        msg['From'] = CONFIG.EMAIL_USER
        msg['To'] = CONFIG.NOTIFICATION_EMAIL
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = f"🚨 Nuevo Evento Adverso Reportado - {report_data['paciente']['nombre']}"
        
        # Crear contenido del email
        email_body = f"""
        NUEVO REPORTE DE EVENTO ADVERSO
        
        📋 Información del Reporte:
        - Fecha del evento: {report_data['contexto']['fecha_evento']}
        - Turno: {report_data['contexto']['turno']}
        - Ubicación: {report_data['contexto']['ubicacion']}
        
        👨‍⚕️ Paciente:
        - Nombre: {report_data['paciente']['nombre']}
        - Edad: {report_data['paciente']['edad']}
        - Expediente: {report_data['paciente']['expediente']}
        
        ⚠️ Evento:
        - Tipo: {report_data['clasificacion']['categoria_principal']}
        - Subcategoría: {report_data['clasificacion']['subcategoria']}
        - Gravedad: {report_data['clasificacion']['gravedad']}
        
        👤 Reportado por:
        - Nombre: {user_info['nombre']}
        - Número económico: {user_info['numero_economico']}
        - Puesto: {user_info['puesto']}
        
        📝 Descripción:
        {report_data['descripcion']['narrativa'][:500]}...
        
        Este es a mensaje automático. Por favor no responder.
        """
        
        msg.attach(MIMEText(email_body, 'plain'))
        
        # Crear contexto SSL seguro
        context = ssl.create_default_context()
        
        # Enviar email
        with smtplib.SMTP_SSL(CONFIG.SMTP_SERVER, CONFIG.SMTP_PORT, context=context) as server:
            server.login(CONFIG.EMAIL_USER, CONFIG.EMAIL_PASSWORD)
            server.send_message(msg)
            
        return True
        
    except Exception as e:
        st.error(f"Error enviando notificación por email: {str(e)}")
        if CONFIG.DEBUG_MODE:
            st.error("Detalles del error:")
            st.error(f"SMTP Server: {CONFIG.SMTP_SERVER}:{CONFIG.SMTP_PORT}")
            st.error(f"From: {CONFIG.EMAIL_USER}")
            st.error(f"To: {CONFIG.NOTIFICATION_EMAIL}")
        return False

# ====================
# FUNCIONES PRINCIPALES
# ====================
def show_capture_form(user_info):
    """Muestra el formulario de captura de eventos adversos"""
    st.title("📝 Sistema de Eventos Adversos - Modo Registro")

    # Si ya se envió un reporte, mostrar opción para crear uno nuevo
    if st.session_state.report_data is not None:
        st.balloons()
        st.success("🎉 Reporte completado exitosamente!")

        # Mostrar información del reporte creado
        if 'metadata' in st.session_state.report_data:
            metadata = st.session_state.report_data['metadata']
            st.info(f"📁 Archivo guardado como: {metadata.get('archivo', 'N/A')}")
            st.info(f"🕐 Fecha de reporte: {metadata.get('fecha_reporte', 'N/A')}")

        # Botón para crear nuevo reporte (FUERA de cualquier formulario)
        if st.button("📋 Crear nuevo reporte", type="primary"):
            st.session_state.report_data = None
            st.session_state.form_submitted = False
            st.rerun()

        return

    # Inicializar session_state para preservar datos del formulario
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {}

    # Formulario principal de captura - SIN clear_on_submit para preservar datos
    with st.form("evento_adverso_form"):
        # Mostrar todas las secciones del formulario
        # Usar datos guardados si existen, de lo contrario usar valores por defecto
        contexto = show_event_context(st.session_state.form_data.get('contexto'))
        clasificacion = show_event_classification(st.session_state.form_data.get('clasificacion'))
        factores = show_contributing_factors(st.session_state.form_data.get('factores'))
        paciente = show_patient_data(st.session_state.form_data.get('paciente'))
        clinica = show_clinical_data(st.session_state.form_data.get('clinica'))
        descripcion = show_event_description(st.session_state.form_data.get('descripcion'))
        acciones = show_immediate_actions(st.session_state.form_data.get('acciones'))
        seguimiento = show_followup_plan(st.session_state.form_data.get('seguimiento'))
        documentacion = show_documentation(st.session_state.form_data.get('documentacion'))
        notificaciones = show_notification(st.session_state.form_data.get('notificaciones'))
        certificado_defuncion = show_death_certificate(st.session_state.form_data.get('certificado_defuncion'))

        # Separador antes del botón de envío
        st.markdown("---")

        # Botón de envío del formulario
        submitted = st.form_submit_button("📤 Enviar Reporte", type="primary", use_container_width=True)

        if submitted:
            # Validar campos obligatorios
            validation_errors = []

            if not paciente['nombre'] or paciente['nombre'].strip() == '':
                validation_errors.append("❌ El nombre del paciente es obligatorio")

            if not clasificacion['categoria_principal'] or clasificacion['categoria_principal'].strip() == '':
                validation_errors.append("❌ La categoría principal del evento es obligatoria")

            if not descripcion['narrativa'] or descripcion['narrativa'].strip() == '':
                validation_errors.append("❌ La descripción narrativa del evento es obligatoria")

            # Mostrar todos los errores de validación
            if validation_errors:
                for error in validation_errors:
                    st.error(error)

                # Guardar datos actuales del formulario en session_state para preservarlos
                st.session_state.form_data = {
                    'contexto': contexto,
                    'clasificacion': clasificacion,
                    'factores': factores,
                    'paciente': paciente,
                    'clinica': clinica,
                    'descripcion': descripcion,
                    'acciones': acciones,
                    'seguimiento': seguimiento,
                    'documentacion': documentacion,
                    'notificaciones': notificaciones,
                    'certificado_defuncion': certificado_defuncion
                }
                st.info("💾 Los datos del formulario han sido guardados. Corrige los errores y envía nuevamente.")
                return

            # Crear estructura de datos del reporte
            report_data = {
                'contexto': contexto,
                'clasificacion': clasificacion,
                'factores': factores,
                'paciente': paciente,
                'clinica': clinica,
                'descripcion': descripcion,
                'acciones': acciones,
                'seguimiento': seguimiento,
                'documentacion': documentacion,
                'notificaciones': notificaciones,
                'certificado_defuncion': certificado_defuncion
            }

            # Guardar reporte
            with st.spinner("💾 Guardando reporte..."):
                if save_report_to_json(report_data, user_info):
                    # Limpiar datos del formulario guardados
                    if 'form_data' in st.session_state:
                        del st.session_state.form_data

                    st.session_state.report_data = report_data
                    st.session_state.form_submitted = True
                    st.rerun()
                else:
                    st.error("❌ Error al guardar el reporte. Por favor, intente nuevamente.")

                    # Guardar datos actuales del formulario en session_state para preservarlos
                    st.session_state.form_data = {
                        'contexto': contexto,
                        'clasificacion': clasificacion,
                        'factores': factores,
                        'paciente': paciente,
                        'clinica': clinica,
                        'descripcion': descripcion,
                        'acciones': acciones,
                        'seguimiento': seguimiento,
                        'documentacion': documentacion,
                        'notificaciones': notificaciones,
                        'certificado_defuncion': certificado_defuncion
                    }

# ====================
# APLICACIÓN PRINCIPAL
# ====================
def obtener_turno_laboral(user_info):
    """Obtiene el turno laboral del archivo de claves"""
    try:
        claves_df = load_csv_data(CONFIG.FILES["claves"])
        if claves_df is None:
            st.error("❌ No se pudo cargar el archivo de claves")
            return None

        # Limpiar y convertir a string para comparación
        claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
        numero_clean = user_info['numero_economico'].strip()

        # Buscar el registro del usuario
        usuario_clave = claves_df[claves_df['numero_economico'] == numero_clean]

        if usuario_clave.empty:
            st.error(f"❌ Usuario {numero_clean} no encontrado en archivo de claves")
            return None

        # Obtener turno laboral
        turno_laboral = usuario_clave.iloc[0]['turno_laboral']

        return turno_laboral

    except Exception as e:
        st.error(f"❌ Error obteniendo turno laboral: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return None

def obtener_servicio_usuario(user_info):
    """Obtiene el servicio del usuario del archivo de enfermeras"""
    try:
        enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"])
        if enfermeras_df is None:
            st.error("❌ No se pudo cargar el archivo de enfermeras")
            return None

        # Limpiar y convertir a string para comparación
        enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
        numero_clean = user_info['numero_economico'].strip()

        # Buscar el registro del usuario
        usuario_enfermera = enfermeras_df[enfermeras_df['numero_economico'] == numero_clean]

        if usuario_enfermera.empty:
            st.error(f"❌ Usuario {numero_clean} no encontrado en archivo de enfermeras")
            return None

        servicio = usuario_enfermera.iloc[0]['servicio']
        return servicio

    except Exception as e:
        st.error(f"❌ Error obteniendo servicio: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return None

# ====================
# APLICACIÓN PRINCIPAL
# ====================
def main():
    # Configuración de la página
    st.set_page_config(
        page_title="Sistema de Eventos Adversos - Modo Registro",
        page_icon="⚠️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # CSS personalizado
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #2c3e50;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid #3498db;
        padding-bottom: 0.5rem;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #c3e6cb;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #ffeaa7;
        margin: 1rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

    # Título principal
    st.markdown('<h1 class="main-header">⚠️ Sistema de Reporte de Eventos Adversos</h1>', unsafe_allow_html=True)

    # Inicializar variables de session_state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'report_data' not in st.session_state:
        st.session_state.report_data = None
    if 'form_submitted' not in st.session_state:
        st.session_state.form_submitted = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'ultimo_inicio_jornada' not in st.session_state:
        st.session_state.ultimo_inicio_jornada = None

    # Verificar autenticación
    if not st.session_state.authenticated:
        authenticated, user_info = authenticate_user()
        if authenticated:
            st.session_state.authenticated = True
            st.session_state.user_info = user_info
            st.rerun()
        else:
            return  # Salir si no está autenticado
    else:
        # Usuario autenticado - mostrar opciones principales
        user_info = st.session_state.user_info

        # Sidebar con información del usuario
        with st.sidebar:
            st.success(f"👤 Usuario: {user_info['nombre']}")
            st.info(f"🔢 Número económico: {user_info['numero_economico']}")
            st.info(f"🏢 Puesto: {user_info['puesto']}")

            # Separador
            st.markdown("---")

            # === PREGUNTA DE INICIO DE JORNADA ===
            manejar_inicio_jornada(user_info)

            # Separador
            st.markdown("---")

            # Selección de modo (ESTAS SON LAS OPCIONES PRINCIPALES)
            app_mode = st.radio(
                "Seleccione el modo:",
                ["📝 Captura de Evento", "🔄 Actualización de Eventos", "👁️ Visualización de Reportes"]
            )

            # Separador
            st.markdown("---")

            # Botones adicionales de utilidad
            if CONFIG.DEBUG_MODE:
                st.markdown("### 🛠️ Herramientas de Debug")
                if st.button("🔍 Probar Conexión SFTP", use_container_width=True):
                    SSHManager.test_connection()

                if st.button("📋 Listar Archivos Remotos", use_container_width=True):
                    files = SSHManager.list_remote_files("*.json", user_info['numero_economico'])
                    if files:
                        st.info(f"Archivos JSON encontrados: {len(files)}")
                        for file in files:
                            st.write(f"- {file}")
                    else:
                        st.info("No se encontraron archivos JSON")

            # Separador
            st.markdown("---")

            # Botón de cerrar sesión
            if st.button("🚪 Cerrar Sesión", use_container_width=True, type="secondary"):
                # Limpiar todas las variables de sesión
                keys_to_preserve = ['debug_mode', 'supervisor_mode']  # Preservar configuraciones
                current_state = {k: v for k, v in st.session_state.items() if k in keys_to_preserve}

                for key in list(st.session_state.keys()):
                    if key not in keys_to_preserve:
                        del st.session_state[key]

                # Restaurar configuraciones
                for key, value in current_state.items():
                    st.session_state[key] = value

                st.rerun()

        # Mostrar el formulario correspondiente al modo seleccionado
        if app_mode == "📝 Captura de Evento":
            show_capture_form(user_info)
        elif app_mode == "🔄 Actualización de Eventos":
            show_update_form(user_info)
        else:  # Visualización de Reportes
            show_view_reports(user_info)

        # Footer informativo
        st.markdown("---")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.caption("© 2024 Sistema de Reporte de Eventos Adversos")
            if CONFIG.DEBUG_MODE:
                st.caption(f"Modo Debug: Activado | Versión: 10c | Usuario: {user_info['numero_economico']}")

if __name__ == "__main__":
    main()        
