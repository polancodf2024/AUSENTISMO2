from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
import streamlit as st
import pandas as pd
import os
from datetime import datetime, timedelta, time
import tempfile
import paramiko
from io import StringIO
import pytz
import numpy as np
import time
import hashlib
import re
import uuid
import base64
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ====================
# CONFIGURACIÓN INICIAL
# ====================
class Config:
    def __init__(self):
        # SFTP Configuration
        self.REMOTE = {
            'HOST': st.secrets["remote_host"],
            'USER': st.secrets["remote_user"],
            'PASSWORD': st.secrets["remote_password"],
            'PORT': st.secrets["remote_port"],
            'DIR': st.secrets["remote_dir"],
            'TIMEOUT_SECONDS': 30
        }
        
        # File Configuration - Usando secrets.toml
        self.FILES = {
            "claves": st.secrets["file_creacion_enfermeras2"],
            "asistencia": st.secrets["file_enfermeras2"]
        }
        
        # App Configuration
        self.DEBUG_MODE = st.secrets.get("debug_mode", False)
        
        # Turnos disponibles
        self.TURNOS = [
            "Matutino (7:00-15:00)",
            "Vespertino (14:30-21:00)",
            "Nocturno (A y B) (20:30-8:00)",
            "Jornada Acumulada (8:00-20:00)"
        ]
        
        # Puestos disponibles
        self.PUESTOS = [
            "jefatura departamento",
            "supervision turno", 
            "jefatura servicio",
            "enfermera general A",
            "enfermera general B",
            "enfermera general C",
            "enfermera especialista",
            "ayudante general",
            "camillero"
        ]
        
        # Servicios disponibles
        self.SERVICIOS = [
            "CEyE-Hospitalización",
            "Diagnóstico",
            "Urgencias",
            "Quirófanos",
            "Cuidados Intensivos",
            "Hospitalización",
            "Consulta Externa",
            "Otro"
        ]
        
        # Opciones de suplencia
        self.SUPLENCIA_OPCIONES = ["SI", "NO"]
        
        # Opciones de incidencias
        self.INCIDENCIAS = {
            "DS": "Descanso",
            "VA": "Vacaciones",
            "VR": "Vacaciones de riesgo",
            "VP": "Vacaciones de premio",
            "ON": "Onomástico",
            "DE": "Económico",
            "AC": "Académico",
            "BE": "Beca",
            "FE": "Festivo",
            "CO": "Comisión Oficial",
            "FA": "Falta",
            "SU": "Suplencia",
            "SL": "Suspensión laboral",
            "IN": "Incapacidad",
            "IG": "Incapacidad por gravidez",
            "CM": "Cuidados Maternos",
            "LC": "Licencia con goce de sueldo",
            "LS": "Licencia sin goce de sueldo",
            "LI": "Licencia sindical",
            "NC": "Comisión Sindical"
        }
        
        # Horas disponibles para hora_entrada
        self.HORAS_ENTRADA = [
            "NO",
            "6:00", "6:05", "6:10", "6:15", "6:20", "6:25", "6:30", "6:35", "6:40", "6:45", "6:50", "6:55",
            "7:00", "7:05", "7:10", "7:15", "7:20", "7:25", "7:30", "7:35", "7:40", "7:45", "7:50", "7:55",
            "8:00", "8:05", "8:10", "8:15", "8:20", "8:25", "8:30", "8:35", "8:40", "8:45", "8:50", "8:55",
            "9:00", "9:05", "9:10", "9:15", "9:20", "9:25", "9:30", "9:35", "9:40", "9:45", "9:50", "9:55",
            "10:00", "10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40", "10:45", "10:50", "10:55",
            "11:00", "11:05", "11:10", "11:15", "11:20", "11:25", "11:30", "11:35", "11:40", "11:45", "11:50", "11:55",
            "12:00", "12:05", "12:10", "12:15", "12:20", "12:25", "12:30", "12:35", "12:40", "12:45", "12:50", "12:55",
            "13:00", "13:05", "13:10", "13:15", "13:20", "13:25", "13:30", "13:35", "13:40", "13:45", "13:50", "13:55",
            "14:00", "14:05", "14:10", "14:15", "14:20", "14:25", "14:30", "14:35", "14:40", "14:45", "14:50", "14:55",
            "15:00", "15:05", "15:10", "15:15", "15:20", "15:25", "15:30", "15:35", "15:40", "15:45", "15:50", "15:55",
            "16:00", "16:05", "16:10", "16:15", "16:20", "16:25", "16:30", "16:35", "16:40", "16:45", "16:50", "16:55",
            "17:00", "17:05", "17:10", "17:15", "17:20", "17:25", "17:30", "17:35", "17:40", "17:45", "17:50", "17:55",
            "18:00", "18:05", "18:10", "18:15", "18:20", "18:25", "18:30", "18:35", "18:40", "18:45", "18:50", "18:55",
            "19:00", "19:05", "19:10", "19:15", "19:20", "19:25", "19:30", "19:35", "19:40", "19:45", "19:50", "19:55",
            "20:00", "20:05", "20:10", "20:15", "20:20", "20:25", "20:30", "20:35", "20:40", "20:45", "20:50", "20:55",
            "21:00", "21:05", "21:10", "21:15", "21:20", "21:25", "21:30", "21:35", "21:40", "21:45", "21:50", "21:55"
        ]

CONFIG = Config()

# ====================
# FUNCIONES DE SEGURIDAD Y AUTENTICACIÓN
# ====================
def sanitize_input(input_data, max_length=100):
    """Sanitiza entradas para prevenir inyección"""
    if not isinstance(input_data, str):
        return ""
    
    # Remover caracteres peligrosos
    sanitized = re.sub(r'[;|&$`<>{}]', '', input_data)
    # Limitar longitud
    return sanitized[:max_length].strip()

def constant_time_compare(val1, val2):
    """Comparación en tiempo constante para prevenir timing attacks"""
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

def authenticate_user():
    """Autentica al usuario con medidas de seguridad"""
    st.title("🔐 Sistema de Administración - Archivo de Claves")

    if 'auth_stage' not in st.session_state:
        st.session_state.auth_stage = 'numero_economico'
        st.session_state.auth_attempts = 0
        st.session_state.last_auth_attempt = 0

    # Prevenir brute force
    current_time = time.time()
    if (st.session_state.auth_attempts >= 3 and
        current_time - st.session_state.last_auth_attempt < 300):
        st.error("🔒 Demasiados intentos fallidos. Espere 5 minutos antes de intentar nuevamente.")
        return False, None

    if st.session_state.auth_stage == 'numero_economico':
        with st.form("auth_form_numero"):
            numero_economico = st.text_input("Número Económico", max_chars=10)
            numero_economico = sanitize_input(numero_economico)

            submitted = st.form_submit_button("Verificar")

            if submitted:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not numero_economico:
                    st.error("Por favor ingrese su número económico")
                    return False, None

                st.session_state.numero_economico = numero_economico
                numero_clean = numero_economico.strip()

                # Cargar archivo de claves
                claves_df = cargar_archivo_claves()
                if claves_df is None:
                    st.error("No se pudieron cargar los archivos necesarios")
                    return False, None

                # Buscar usuario en archivo de claves
                user_clave = claves_df[claves_df['numero_economico'] == numero_clean]
                if user_clave.empty:
                    st.error("❌ Número económico no registrado")
                    return False, None

                # Obtener datos del usuario
                puesto = user_clave.iloc[0]['puesto'].strip().lower() if 'puesto' in user_clave.columns and not pd.isna(user_clave.iloc[0]['puesto']) else ""
                nombre_completo = user_clave.iloc[0]['nombre_completo'].strip() if 'nombre_completo' in user_clave.columns and not pd.isna(user_clave.iloc[0]['nombre_completo']) else ""
                turno_laboral = user_clave.iloc[0]['turno_laboral'].strip() if 'turno_laboral' in user_clave.columns and not pd.isna(user_clave.iloc[0]['turno_laboral']) else ""

                # Verificar que sea administración
                if puesto != "administración":
                    st.error("❌ Solo personal con puesto 'administración' puede acceder al sistema")
                    return False, None

                st.session_state.auth_stage = 'password'
                st.session_state.user_data = {
                    'numero_economico': numero_clean,
                    'puesto': puesto,
                    'nombre_completo': nombre_completo,
                    'turno_laboral': turno_laboral
                }

                if CONFIG.DEBUG_MODE:
                    st.write(f"DEBUG: Datos capturados - Nombre: '{nombre_completo}', Puesto: '{puesto}', Turno: '{turno_laboral}'")

                st.rerun()

    elif st.session_state.auth_stage == 'password':
        with st.form("auth_form_password"):
            user_data = st.session_state.user_data
            st.info(f"👤 Usuario: {user_data['numero_economico']}")
            st.info(f"📝 Nombre: {user_data['nombre_completo']}")
            st.info(f"👔 Puesto: {user_data['puesto']}")
            if user_data.get('turno_laboral'):
                st.info(f"🕒 Turno: {user_data['turno_laboral']}")

            password = st.text_input("Contraseña", type="password")
            confirm = st.form_submit_button("Validar Contraseña")

            if confirm:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not password:
                    st.error("❌ Por favor ingrese su contraseña")
                    return False, None

                claves_df = cargar_archivo_claves()
                if claves_df is None:
                    st.error("No se pudo cargar el archivo de claves")
                    return False, None

                # Buscar usuario en archivo de claves
                user_clave = claves_df[claves_df['numero_economico'] == st.session_state.numero_economico]
                if user_clave.empty:
                    st.error("❌ Usuario no encontrado en archivo de claves")
                    return False, None

                # Verificar contraseña
                if 'password' not in user_clave.columns:
                    st.error("❌ Error en la estructura del archivo de claves")
                    return False, None

                if not constant_time_compare(str(user_clave.iloc[0]['password']), password):
                    st.error("❌ Contraseña incorrecta")
                    return False, None

                # Autenticación exitosa
                st.session_state.auth_attempts = 0
                st.success("✅ Autenticación exitosa")
                st.session_state.auth_stage = 'authenticated'
                st.rerun()

    elif st.session_state.auth_stage == 'authenticated':
        return True, st.session_state.user_data

    return False, None

# ====================
# FUNCIONES SSH/SFTP
# ====================
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
            return None

    @staticmethod
    def get_remote_file(remote_filename):
        """Lee archivo remoto con manejo de errores"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return None

        try:
            sftp = ssh.open_sftp()
            remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

            with sftp.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8')

            return content
        except FileNotFoundError:
            # Si el archivo no existe, devolver contenido vacío
            return ""
        except Exception as e:
            st.error(f"Error leyendo archivo remoto: {str(e)}")
            return None
        finally:
            ssh.close()

    @staticmethod
    def put_remote_file(remote_path, content):
        """Escribe archivo remoto con manejo de errores"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return False

        try:
            sftp = ssh.open_sftp()

            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                sftp.put(temp_file_path, remote_path)
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

# ====================
# FUNCIONES DE ARCHIVOS
# ====================
def cargar_archivo_claves():
    """Carga el archivo de claves con estructura completa"""
    content = SSHManager.get_remote_file(CONFIG.FILES["claves"])
    if content is None:
        return None

    # Definir estructura completa esperada según el layout proporcionado
    columnas_completas = [
        'numero_economico', 'puesto', 'nombre_completo', 'servicio', 
        'turno_laboral', 'password', 'correo_electronico', 'suplencia',
        'numero_evento', 'numero_consecutivo'
    ]

    if content.strip() == "":
        # Devolver DataFrame vacío con todas las columnas esperadas
        return pd.DataFrame(columns=columnas_completas)

    try:
        df = pd.read_csv(StringIO(content))

        # Asegurar que todas las columnas existan
        for col in columnas_completas:
            if col not in df.columns:
                if col in ['numero_consecutivo', 'numero_evento']:
                    df[col] = 1  # Valores por defecto según requerimiento
                elif col == 'suplencia':
                    df[col] = "NO"  # Valor por defecto para suplencia
                else:
                    df[col] = ""  # Valores por defecto para campos de texto

        # Limpiar y normalizar datos con verificación de existencia
        if 'numero_economico' in df.columns:
            df['numero_economico'] = df['numero_economico'].astype(str).str.strip()
        else:
            df['numero_economico'] = ""

        if 'nombre_completo' in df.columns:
            df['nombre_completo'] = df['nombre_completo'].astype(str).str.strip()
        else:
            df['nombre_completo'] = ""

        if 'puesto' in df.columns:
            df['puesto'] = df['puesto'].astype(str).str.strip().str.lower()
        else:
            df['puesto'] = ""

        if 'servicio' in df.columns:
            df['servicio'] = df['servicio'].astype(str).str.strip()
        else:
            df['servicio'] = ""

        if 'password' in df.columns:
            df['password'] = df['password'].astype(str).str.strip()
        else:
            df['password'] = ""

        if 'turno_laboral' in df.columns:
            df['turno_laboral'] = df['turno_laboral'].astype(str).str.strip()
        else:
            df['turno_laboral'] = ""

        if 'correo_electronico' in df.columns:
            df['correo_electronico'] = df['correo_electronico'].astype(str).str.strip()
        else:
            df['correo_electronico'] = ""

        if 'suplencia' in df.columns:
            df['suplencia'] = df['suplencia'].astype(str).str.strip().str.upper()
            # Asegurar que los valores de suplencia sean válidos
            df['suplencia'] = df['suplencia'].apply(lambda x: x if x in ['SI', 'NO'] else 'NO')
        else:
            df['suplencia'] = "NO"

        if 'numero_consecutivo' in df.columns:
            df['numero_consecutivo'] = df['numero_consecutivo'].fillna(1).astype(int)
        else:
            df['numero_consecutivo'] = 1

        if 'numero_evento' in df.columns:
            df['numero_evento'] = df['numero_evento'].fillna(1).astype(int)
        else:
            df['numero_evento'] = 1

        return df

    except Exception as e:
        st.error(f"Error procesando archivo {CONFIG.FILES['claves']}: {str(e)}")
        # En caso de error, devolver DataFrame vacío con estructura correcta
        return pd.DataFrame(columns=columnas_completas)

def cargar_archivo_asistencia():
    """Carga el archivo de asistencia con estructura completa"""
    content = SSHManager.get_remote_file(CONFIG.FILES["asistencia"])
    if content is None:
        return None

    # Definir estructura completa esperada según el layout proporcionado
    columnas_completas = [
        'fecha', 'fecha_turno', 'numero_economico', 'puesto', 'nombre_completo', 
        'servicio', 'turno_laboral', 'hora_entrada', 'incidencias', 'suplencia'
    ]

    if content.strip() == "":
        # Devolver DataFrame vacío con todas las columnas esperadas
        return pd.DataFrame(columns=columnas_completas)

    try:
        df = pd.read_csv(StringIO(content))

        # Asegurar que todas las columnas existan
        for col in columnas_completas:
            if col not in df.columns:
                df[col] = ""  # Valores por defecto para campos de texto

        # Limpiar y normalizar datos con verificación de existencia
        if 'numero_economico' in df.columns:
            df['numero_economico'] = df['numero_economico'].astype(str).str.strip()
        else:
            df['numero_economico'] = ""

        if 'nombre_completo' in df.columns:
            df['nombre_completo'] = df['nombre_completo'].astype(str).str.strip()
        else:
            df['nombre_completo'] = ""

        if 'puesto' in df.columns:
            df['puesto'] = df['puesto'].astype(str).str.strip().str.lower()
        else:
            df['puesto'] = ""

        if 'servicio' in df.columns:
            df['servicio'] = df['servicio'].astype(str).str.strip()
        else:
            df['servicio'] = ""

        if 'turno_laboral' in df.columns:
            df['turno_laboral'] = df['turno_laboral'].astype(str).str.strip()
        else:
            df['turno_laboral'] = ""

        if 'hora_entrada' in df.columns:
            df['hora_entrada'] = df['hora_entrada'].astype(str).str.strip()
            # Reemplazar 'nan' por cadena vacía
            df['hora_entrada'] = df['hora_entrada'].replace('nan', '')
        else:
            df['hora_entrada'] = ""

        if 'incidencias' in df.columns:
            df['incidencias'] = df['incidencias'].astype(str).str.strip()
            # Reemplazar 'nan' por cadena vacía
            df['incidencias'] = df['incidencias'].replace('nan', '')
        else:
            df['incidencias'] = ""

        if 'suplencia' in df.columns:
            df['suplencia'] = df['suplencia'].astype(str).str.strip().str.upper()
            # Asegurar que los valores de suplencia sean válidos
            df['suplencia'] = df['suplencia'].apply(lambda x: x if x in ['SI', 'NO'] else 'NO')
        else:
            df['suplencia'] = "NO"

        if 'fecha' in df.columns:
            df['fecha'] = df['fecha'].astype(str).str.strip()
        else:
            df['fecha'] = ""

        if 'fecha_turno' in df.columns:
            df['fecha_turno'] = df['fecha_turno'].astype(str).str.strip()
        else:
            df['fecha_turno'] = ""

        return df

    except Exception as e:
        st.error(f"Error procesando archivo {CONFIG.FILES['asistencia']}: {str(e)}")
        # En caso de error, devolver DataFrame vacío con estructura correcta
        return pd.DataFrame(columns=columnas_completas)

def guardar_archivo_claves(df):
    """Guarda el archivo de claves de enfermeras"""
    remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["claves"])
    csv_content = df.to_csv(index=False)

    if SSHManager.put_remote_file(remote_path, csv_content):
        if CONFIG.DEBUG_MODE:
            st.info("✅ Archivo de claves guardado correctamente")
        return True
    else:
        st.error("❌ Error al guardar el archivo de claves")
        return False

def guardar_archivo_asistencia(df):
    """Guarda el archivo de asistencia"""
    remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["asistencia"])
    csv_content = df.to_csv(index=False)

    if SSHManager.put_remote_file(remote_path, csv_content):
        if CONFIG.DEBUG_MODE:
            st.info("✅ Archivo de asistencia guardado correctamente")
        return True
    else:
        st.error("❌ Error al guardar el archivo de asistencia")
        return False

def crear_registro_asistencia_manual(numero_economico, hora_entrada, incidencias):
    """Crea un registro manual en el archivo de asistencia con los datos específicos"""
    try:
        # Cargar archivo de asistencia
        df_asistencia = cargar_archivo_asistencia()
        if df_asistencia is None:
            return False

        # Obtener fecha actual
        fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M")
        fecha_turno_actual = datetime.now().strftime("%Y-%m-%d")

        # Cargar datos del usuario desde claves para obtener información completa
        df_claves = cargar_archivo_claves()
        if df_claves is None:
            return False

        usuario_clave = df_claves[df_claves['numero_economico'] == numero_economico]
        if usuario_clave.empty:
            return False

        usuario = usuario_clave.iloc[0]

        # Eliminar cualquier registro existente para este usuario en la fecha actual (evitar duplicados)
        df_asistencia = df_asistencia[
            ~((df_asistencia['numero_economico'] == numero_economico) & 
              (df_asistencia['fecha_turno'] == fecha_turno_actual))
        ]

        # Crear nuevo registro de asistencia
        nuevo_registro_asistencia = {
            'fecha': fecha_actual,
            'fecha_turno': fecha_turno_actual,
            'numero_economico': numero_economico,
            'puesto': usuario['puesto'],
            'nombre_completo': usuario['nombre_completo'],
            'servicio': usuario['servicio'],
            'turno_laboral': usuario['turno_laboral'],
            'hora_entrada': hora_entrada,
            'incidencias': incidencias,
            'suplencia': usuario['suplencia']
        }

        # Agregar nuevo registro
        df_asistencia = pd.concat([df_asistencia, pd.DataFrame([nuevo_registro_asistencia])], ignore_index=True)

        # Guardar archivo de asistencia
        return guardar_archivo_asistencia(df_asistencia)

    except Exception as e:
        st.error(f"Error creando registro de asistencia: {str(e)}")
        return False

def actualizar_registro_asistencia_manual(numero_original, nuevo_numero, hora_entrada, incidencias):
    """Actualiza el registro en asistencia con los nuevos datos"""
    try:
        # Cargar archivo de asistencia
        df_asistencia = cargar_archivo_asistencia()
        if df_asistencia is None:
            return False

        # Obtener fecha actual
        fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M")
        fecha_turno_actual = datetime.now().strftime("%Y-%m-%d")

        # Cargar datos del usuario actualizado desde claves
        df_claves = cargar_archivo_claves()
        if df_claves is None:
            return False

        usuario_clave = df_claves[df_claves['numero_economico'] == nuevo_numero]
        if usuario_clave.empty:
            return False

        usuario = usuario_clave.iloc[0]

        # Buscar y eliminar registros existentes para evitar duplicados
        mask_original = (df_asistencia['numero_economico'] == numero_original) & (df_asistencia['fecha_turno'] == fecha_turno_actual)
        mask_nuevo = (df_asistencia['numero_economico'] == nuevo_numero) & (df_asistencia['fecha_turno'] == fecha_turno_actual)
        
        # Eliminar registros existentes
        df_asistencia = df_asistencia[~(mask_original | mask_nuevo)]

        # Crear nuevo registro
        nuevo_registro = {
            'fecha': fecha_actual,
            'fecha_turno': fecha_turno_actual,
            'numero_economico': nuevo_numero,
            'puesto': usuario['puesto'],
            'nombre_completo': usuario['nombre_completo'],
            'servicio': usuario['servicio'],
            'turno_laboral': usuario['turno_laboral'],
            'hora_entrada': hora_entrada,
            'incidencias': incidencias,
            'suplencia': usuario['suplencia']
        }
        
        df_asistencia = pd.concat([df_asistencia, pd.DataFrame([nuevo_registro])], ignore_index=True)

        # Guardar archivo de asistencia
        return guardar_archivo_asistencia(df_asistencia)

    except Exception as e:
        st.error(f"Error actualizando registro de asistencia: {str(e)}")
        return False

def sincronizar_baja_asistencia(numero_economico_eliminado):
    """Sincroniza la baja de un usuario con el archivo de asistencia"""
    try:
        # Cargar archivo de asistencia existente
        df_asistencia = cargar_archivo_asistencia()
        
        if df_asistencia is None:
            return False
            
        # Obtener fecha actual para el turno
        fecha_turno_actual = datetime.now().strftime("%Y-%m-%d")
        
        # Eliminar registros del usuario en asistencia para la fecha actual
        df_asistencia_actualizado = df_asistencia[
            ~((df_asistencia['numero_economico'] == numero_economico_eliminado) & 
              (df_asistencia['fecha_turno'] == fecha_turno_actual))
        ]
        
        # Guardar archivo de asistencia actualizado
        return guardar_archivo_asistencia(df_asistencia_actualizado)
        
    except Exception as e:
        st.error(f"Error en sincronización de baja con asistencia: {str(e)}")
        return False

# ====================
# FUNCIONES DE INTERFAZ
# ====================
def mostrar_creacion_claves(user_info):
    """Muestra la interfaz para creación de registros en archivo de claves"""
    st.header("📝 Creación de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    with st.form("form_creacion_claves", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            numero_economico = st.text_input("Número Económico*", max_chars=10, key="num_economico_claves")
            puesto = st.selectbox(
                "Puesto*",
                options=CONFIG.PUESTOS,
                key="puesto_select_claves"
            )
            servicio = st.selectbox(
                "Servicio*",
                options=CONFIG.SERVICIOS,
                key="servicio_select_claves"
            )
            turno_laboral = st.selectbox("🕒 Turno laboral*", CONFIG.TURNOS, key="turno_select_claves")

        with col2:
            nombre_completo = st.text_input("Nombre Completo*", key="nombre_completo_claves")
            correo_electronico = st.text_input("Correo Electrónico", key="correo_claves")
            suplencia = st.selectbox("Suplencia*", options=CONFIG.SUPLENCIA_OPCIONES, key="suplencia_select_claves")
            password = st.text_input("Contraseña*", type="password", key="password_claves")
            password_confirm = st.text_input("Confirmar Contraseña*", type="password", key="password_confirm_claves")

        # Campos adicionales para asistencia
        st.markdown("---")
        st.subheader("📋 Datos de Asistencia")
        
        col3, col4 = st.columns(2)
        
        with col3:
            hora_entrada = st.selectbox(
                "Hora de Entrada*",
                options=CONFIG.HORAS_ENTRADA,
                index=0,  # Por defecto "NO"
                key="hora_entrada_claves"
            )
            
        with col4:
            # Crear opciones para incidencias
            opciones_incidencias = ["NO"] + [f"{codigo} - {descripcion}" for codigo, descripcion in CONFIG.INCIDENCIAS.items()]
            incidencia_seleccionada = st.selectbox(
                "Incidencias*",
                options=opciones_incidencias,
                index=0,  # Por defecto "NO"
                key="incidencias_claves"
            )
            
            # Procesar la selección de incidencias
            if incidencia_seleccionada == "NO":
                incidencia_final = "NO"
            else:
                incidencia_final = incidencia_seleccionada.split(" - ")[0]

        submitted = st.form_submit_button("➕ Agregar Usuario", type="primary")

        if submitted:
            # Validar que todos los campos obligatorios estén llenos
            campos_obligatorios = [
                numero_economico.strip(),
                puesto.strip(),
                nombre_completo.strip(),
                servicio.strip(),
                password.strip(),
                password_confirm.strip(),
                turno_laboral.strip() if turno_laboral else "",
                hora_entrada.strip() if hora_entrada else "",
                incidencia_final.strip() if incidencia_final else ""
            ]

            # Verificar campos vacíos
            campos_vacios = []
            for i, campo in enumerate(campos_obligatorios):
                if not campo:
                    nombres_campos = [
                        "Número Económico", "Puesto", "Nombre Completo", "Servicio", 
                        "Contraseña", "Confirmar Contraseña", "Turno Laboral",
                        "Hora de Entrada", "Incidencias"
                    ]
                    campos_vacios.append(nombres_campos[i])

            if campos_vacios:
                st.error(f"❌ Por favor complete todos los campos obligatorios (*). Faltante: {', '.join(campos_vacios)}")
                if CONFIG.DEBUG_MODE:
                    st.write("Valores de campos:", campos_obligatorios)
                return

            # Verificar que las contraseñas coincidan
            if password != password_confirm:
                st.error("❌ Las contraseñas no coinciden")
                return

            # Verificar si el número económico ya existe
            if numero_economico in df['numero_economico'].values:
                st.error(f"❌ El número económico {numero_economico} ya existe")
                return

            # Agregar nuevo registro al archivo de claves
            nuevo_registro = pd.DataFrame({
                'numero_economico': [numero_economico.strip()],
                'puesto': [puesto.strip()],
                'nombre_completo': [nombre_completo.strip()],
                'servicio': [servicio.strip()],
                'turno_laboral': [turno_laboral.strip()],
                'password': [password.strip()],
                'correo_electronico': [correo_electronico.strip()],
                'suplencia': [suplencia],
                'numero_evento': [1],  # Valor fijo 1 según requerimiento
                'numero_consecutivo': [1]  # Valor fijo 1 según requerimiento
            })

            df = pd.concat([df, nuevo_registro], ignore_index=True)

            if guardar_archivo_claves(df):
                # Ahora crear el registro en asistencia con los datos específicos
                if crear_registro_asistencia_manual(numero_economico.strip(), hora_entrada, incidencia_final):
                    st.success("✅ Usuario agregado correctamente al archivo de claves y asistencia")
                else:
                    st.success("✅ Usuario agregado al archivo de claves, pero hubo un error en la asistencia")
                st.rerun()
            else:
                st.error("❌ Error al guardar los datos")

def mostrar_modificacion_claves(user_info):
    """Muestra la interfaz para modificación de registros en archivo de claves"""
    st.header("✏️ Modificación de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay usuarios registrados para modificar")
        return

    # Seleccionar usuario a modificar
    usuarios_options = [f"{row['numero_economico']} - {row['nombre_completo']} - {row['puesto']}"
                       for _, row in df.iterrows()]

    usuario_seleccionado = st.selectbox(
        "Seleccione el usuario a modificar:",
        options=usuarios_options,
        key="modificacion_select_claves"
    )

    numero_economico_seleccionado = usuario_seleccionado.split(" - ")[0].strip()

    # Verificar si el registro existe antes de acceder
    registro_filtrado = df[df['numero_economico'] == numero_economico_seleccionado]

    if registro_filtrado.empty:
        st.error("❌ Error: El usuario seleccionado no existe en los registros")
        return

    registro_original = registro_filtrado.iloc[0]

    # Cargar datos de asistencia para este usuario
    df_asistencia = cargar_archivo_asistencia()
    fecha_turno_actual = datetime.now().strftime("%Y-%m-%d")
    
    registro_asistencia = df_asistencia[
        (df_asistencia['numero_economico'] == numero_economico_seleccionado) &
        (df_asistencia['fecha_turno'] == fecha_turno_actual)
    ]
    
    # Valores por defecto para asistencia
    hora_entrada_actual = "NO"
    incidencias_actual = "NO"
    
    if not registro_asistencia.empty:
        registro = registro_asistencia.iloc[0]
        hora_entrada_actual = registro['hora_entrada'] if pd.notna(registro['hora_entrada']) and registro['hora_entrada'] != '' else "NO"
        incidencias_actual = registro['incidencias'] if pd.notna(registro['incidencias']) and registro['incidencias'] != '' else "NO"

    # Crear sufijo único basado en el número económico para las claves
    key_suffix = f"_{numero_economico_seleccionado}_claves"

    with st.form("form_modificacion_claves"):
        col1, col2 = st.columns(2)

        with col1:
            nuevo_numero = st.text_input("Número Económico*",
                                       value=str(registro_original['numero_economico']),
                                       max_chars=10,
                                       key=f"mod_numero{key_suffix}")

            nuevo_puesto = st.selectbox(
                "Puesto*",
                options=CONFIG.PUESTOS,
                index=CONFIG.PUESTOS.index(registro_original['puesto']) if registro_original['puesto'] in CONFIG.PUESTOS else 0,
                key=f"mod_puesto{key_suffix}"
            )

            nuevo_servicio = st.selectbox(
                "Servicio*",
                options=CONFIG.SERVICIOS,
                index=CONFIG.SERVICIOS.index(registro_original['servicio']) if 'servicio' in registro_original and registro_original['servicio'] in CONFIG.SERVICIOS else 0,
                key=f"mod_servicio{key_suffix}"
            )

            nuevo_turno = st.selectbox(
                "🕒 Turno laboral*",
                options=CONFIG.TURNOS,
                index=CONFIG.TURNOS.index(registro_original['turno_laboral']) if registro_original['turno_laboral'] in CONFIG.TURNOS else 0,
                key=f"mod_turno{key_suffix}"
            )

        with col2:
            nuevo_nombre = st.text_input("Nombre Completo*",
                                       value=registro_original['nombre_completo'],
                                       key=f"mod_nombre{key_suffix}")

            nuevo_correo = st.text_input("Correo Electrónico",
                                       value=registro_original.get('correo_electronico', ''),
                                       key=f"mod_correo{key_suffix}")

            nueva_suplencia = st.selectbox(
                "Suplencia*",
                options=CONFIG.SUPLENCIA_OPCIONES,
                index=CONFIG.SUPLENCIA_OPCIONES.index(registro_original['suplencia']) if 'suplencia' in registro_original and registro_original['suplencia'] in CONFIG.SUPLENCIA_OPCIONES else 1,
                key=f"mod_suplencia{key_suffix}"
            )

            nuevo_password = st.text_input("Nueva Contraseña (dejar vacío para mantener actual)",
                                         type="password",
                                         key=f"mod_password{key_suffix}")

            confirm_password = st.text_input("Confirmar Nueva Contraseña",
                                           type="password",
                                           key=f"mod_confirm_password{key_suffix}")

        # Campos adicionales para asistencia
        st.markdown("---")
        st.subheader("📋 Datos de Asistencia")
        
        col3, col4 = st.columns(2)
        
        with col3:
            # Encontrar índice actual para hora_entrada
            hora_entrada_index = 0
            if hora_entrada_actual in CONFIG.HORAS_ENTRADA:
                hora_entrada_index = CONFIG.HORAS_ENTRADA.index(hora_entrada_actual)
            
            nueva_hora_entrada = st.selectbox(
                "Hora de Entrada*",
                options=CONFIG.HORAS_ENTRADA,
                index=hora_entrada_index,
                key=f"mod_hora_entrada{key_suffix}"
            )
            
        with col4:
            # Crear opciones para incidencias
            opciones_incidencias = ["NO"] + [f"{codigo} - {descripcion}" for codigo, descripcion in CONFIG.INCIDENCIAS.items()]
            
            # Encontrar índice actual para incidencias
            incidencia_index = 0
            if incidencias_actual != "NO":
                # Buscar la incidencia actual en las opciones
                for i, opcion in enumerate(opciones_incidencias):
                    if opcion.startswith(incidencias_actual):
                        incidencia_index = i
                        break
            
            nueva_incidencia_seleccionada = st.selectbox(
                "Incidencias*",
                options=opciones_incidencias,
                index=incidencia_index,
                key=f"mod_incidencias{key_suffix}"
            )
            
            # Procesar la selección de incidencias
            if nueva_incidencia_seleccionada == "NO":
                nueva_incidencia_final = "NO"
            else:
                nueva_incidencia_final = nueva_incidencia_seleccionada.split(" - ")[0]

        submitted = st.form_submit_button("💾 Guardar Cambios")

        if submitted:
            if not all([nuevo_numero, nuevo_puesto, nuevo_nombre, nuevo_servicio, nuevo_turno, nueva_hora_entrada, nueva_incidencia_final]):
                st.error("Por favor complete todos los campos obligatorios (*)")
            else:
                # Limpiar los valores
                nuevo_numero = nuevo_numero.strip()
                nuevo_nombre = nuevo_nombre.strip()
                nuevo_puesto = nuevo_puesto.strip()
                nuevo_servicio = nuevo_servicio.strip()
                nuevo_turno = nuevo_turno.strip()
                nuevo_correo = nuevo_correo.strip()

                # Verificar si el nuevo número económico ya existe (y no es el mismo)
                if (nuevo_numero != numero_economico_seleccionado and
                    any(df['numero_economico'] == nuevo_numero)):
                    st.error(f"El número económico {nuevo_numero} ya existe")
                    return

                # Verificar contraseñas si se proporcionaron
                if nuevo_password:
                    if nuevo_password != confirm_password:
                        st.error("❌ Las contraseñas no coinciden")
                        return
                    password_final = nuevo_password
                else:
                    # Mantener la contraseña actual
                    password_final = registro_original['password']

                # Cargar el archivo completo para modificar
                df_completo = cargar_archivo_claves()
                if df_completo is None:
                    st.error("Error al cargar datos completos")
                    return

                # Actualizar registro en claves
                mask = df_completo['numero_economico'] == numero_economico_seleccionado
                df_completo.loc[mask, 'numero_economico'] = nuevo_numero
                df_completo.loc[mask, 'nombre_completo'] = nuevo_nombre
                df_completo.loc[mask, 'puesto'] = nuevo_puesto
                df_completo.loc[mask, 'servicio'] = nuevo_servicio
                df_completo.loc[mask, 'turno_laboral'] = nuevo_turno
                df_completo.loc[mask, 'password'] = password_final
                df_completo.loc[mask, 'correo_electronico'] = nuevo_correo
                df_completo.loc[mask, 'suplencia'] = nueva_suplencia
                # Mantener los valores de numero_consecutivo y numero_evento
                df_completo.loc[mask, 'numero_consecutivo'] = registro_original['numero_consecutivo']
                df_completo.loc[mask, 'numero_evento'] = registro_original['numero_evento']

                if guardar_archivo_claves(df_completo):
                    # Actualizar registro en asistencia
                    if actualizar_registro_asistencia_manual(numero_economico_seleccionado, nuevo_numero, nueva_hora_entrada, nueva_incidencia_final):
                        st.success("✅ Cambios guardados correctamente y sincronizados con asistencia")
                    else:
                        st.success("✅ Cambios guardados en claves, pero hubo un error en la asistencia")
                    st.rerun()
                else:
                    st.error("❌ Error al guardar los cambios")

def mostrar_baja_claves(user_info):
    """Muestra la interfaz para baja de registros en archivo de claves"""
    st.header("🗑️ Baja de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay usuarios registrados para dar de baja")
        return

    # Seleccionar usuario a eliminar
    usuarios_options = [f"{row['numero_economico']} - {row['nombre_completo']} - {row['puesto']}"
                       for _, row in df.iterrows()]

    if not usuarios_options:
        st.info("No hay usuarios disponibles para eliminar")
        return

    usuario_seleccionado = st.selectbox(
        "Seleccione el usuario a eliminar:",
        options=usuarios_options,
        key="baja_select_claves"
    )

    numero_economico_seleccionado = usuario_seleccionado.split(" - ")[0].strip()
    puesto_seleccionado = usuario_seleccionado.split(" - ")[2].strip()

    # Verificar si el registro existe
    registro_filtrado = df[df['numero_economico'] == numero_economico_seleccionado]
    if registro_filtrado.empty:
        st.error("❌ Error: El usuario seleccionado no existe en los registros")
        return

    registro = registro_filtrado.iloc[0]

    # Mostrar información del usuario seleccionado
    st.info(f"""
    **Información del usuario seleccionado:**
    - **Número Económico:** {registro['numero_economico']}
    - **Nombre:** {registro['nombre_completo']}
    - **Puesto:** {registro['puesto']}
    - **Servicio:** {registro.get('servicio', 'No especificado')}
    - **Turno Laboral:** {registro['turno_laboral']}
    - **Correo Electrónico:** {registro.get('correo_electronico', 'No especificado')}
    - **Suplencia:** {registro.get('suplencia', 'NO')}
    - **N° Consecutivo:** {registro['numero_consecutivo']}
    - **N° Evento:** {registro['numero_evento']}
    """)

    # Advertencia especial para no eliminarse a sí mismo
    if numero_economico_seleccionado == user_info['numero_economico']:
        st.error("⚠️ **ADVERTENCIA CRÍTICA:** No puede eliminarse a sí mismo del sistema")

    # Confirmación explícita antes de eliminar
    confirmacion = st.checkbox("⚠️ Confirmo que deseo eliminar permanentemente este usuario", key="confirmacion_baja_claves")

    if st.button("❌ Eliminar Usuario", type="primary", key="baja_button_claves", disabled=not confirmacion):
        if not confirmacion:
            st.error("Debe confirmar la eliminación primero")
            return

        # Prevenir auto-eliminación
        if numero_economico_seleccionado == user_info['numero_economico']:
            st.error("❌ No puede eliminarse a sí mismo del sistema")
            return

        # Cargar el archivo completo para eliminar
        df_completo = cargar_archivo_claves()
        if df_completo is None:
            st.error("Error al cargar datos completos")
            return

        # Eliminar registro del archivo de claves
        df_claves_actualizado = df_completo[df_completo['numero_economico'] != numero_economico_seleccionado]

        # Guardar archivo de claves actualizado
        if guardar_archivo_claves(df_claves_actualizado):
            # Sincronizar baja con archivo de asistencia
            if sincronizar_baja_asistencia(numero_economico_seleccionado):
                st.success("✅ Usuario eliminado correctamente del archivo de claves y asistencia")
            else:
                st.success("✅ Usuario eliminado del archivo de claves, pero hubo un error en la sincronización con asistencia")
            st.rerun()
        else:
            st.error("❌ Error al eliminar el usuario del archivo de claves")

def mostrar_consulta_claves(user_info):
    """Muestra la interfaz para consulta de registros en archivo de claves"""
    st.header("👥 Consulta de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos del archivo de claves")
        return

    if df.empty:
        st.info("No hay usuarios registrados en el archivo de claves")
        return

    st.write(f"**Total de usuarios registrados:** {len(df)}")

    # Filtros
    col1, col2, col3 = st.columns(3)
    with col1:
        filtro_puesto = st.selectbox(
            "Filtrar por puesto:",
            options=["Todos"] + sorted(df['puesto'].unique()),
            key="filtro_puesto_claves"
        )
    with col2:
        filtro_turno = st.selectbox(
            "Filtrar por turno:",
            options=["Todos"] + sorted(df['turno_laboral'].unique()),
            key="filtro_turno_claves"
        )
    with col3:
        filtro_suplencia = st.selectbox(
            "Filtrar por suplencia:",
            options=["Todos"] + sorted(df['suplencia'].unique()),
            key="filtro_suplencia_claves"
        )

    # Búsqueda por número económico o nombre
    busqueda = st.text_input("Buscar (número o nombre):", key="busqueda_claves")

    # Aplicar filtros
    df_filtrado = df.copy()
    
    if filtro_puesto != "Todos":
        df_filtrado = df_filtrado[df_filtrado['puesto'] == filtro_puesto]
    
    if filtro_turno != "Todos":
        df_filtrado = df_filtrado[df_filtrado['turno_laboral'] == filtro_turno]
    
    if filtro_suplencia != "Todos":
        df_filtrado = df_filtrado[df_filtrado['suplencia'] == filtro_suplencia]
    
    if busqueda:
        busqueda_lower = busqueda.lower()
        mask = (df_filtrado['numero_economico'].str.lower().str.contains(busqueda_lower)) | \
               (df_filtrado['nombre_completo'].str.lower().str.contains(busqueda_lower))
        df_filtrado = df_filtrado[mask]

    if df_filtrado.empty:
        st.info("No hay usuarios que coincidan con los filtros aplicados")
        return

    st.write(f"**Usuarios encontrados:** {len(df_filtrado)}")

    # Mostrar estadísticas
    if not df_filtrado.empty:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total usuarios filtrados", len(df_filtrado))
        with col2:
            puestos_unicos = df_filtrado['puesto'].nunique()
            st.metric("Puestos diferentes", puestos_unicos)
        with col3:
            turnos_unicos = df_filtrado['turno_laboral'].nunique()
            st.metric("Turnos diferentes", turnos_unicos)
        with col4:
            suplencias_count = df_filtrado['suplencia'].value_counts()
            suplencia_mas_comun = suplencias_count.index[0] if not suplencias_count.empty else "N/A"
            st.metric("Suplencia más común", suplencia_mas_comun)

    # Mostrar tabla de datos (ocultando contraseñas por seguridad)
    columnas_a_mostrar = ['numero_economico', 'nombre_completo', 'puesto', 'servicio', 'turno_laboral', 'correo_electronico', 'suplencia', 'numero_consecutivo', 'numero_evento']
    df_display = df_filtrado[columnas_a_mostrar] if all(col in df_filtrado.columns for col in columnas_a_mostrar) else df_filtrado

    st.dataframe(
        df_display,
        column_config={
            "numero_economico": "Número Económico",
            "nombre_completo": "Nombre Completo",
            "puesto": "Puesto",
            "servicio": "Servicio",
            "turno_laboral": "Turno Laboral",
            "correo_electronico": "Correo Electrónico",
            "suplencia": "Suplencia",
            "numero_consecutivo": "N° Consecutivo",
            "numero_evento": "N° Evento"
        },
        hide_index=True,
        use_container_width=True
    )

def mostrar_impresion_claves(user_info):
    """Muestra la interfaz para impresión de registros en archivo de claves"""
    st.header("🖨️ Impresión de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos del archivo de claves")
        return

    if df.empty:
        st.info("No hay usuarios registrados en el archivo de claves")
        return

    # Filtros para impresión
    col1, col2 = st.columns(2)
    with col1:
        filtro_puesto = st.selectbox(
            "Filtrar por puesto:",
            options=["Todos"] + sorted(df['puesto'].unique()),
            key="filtro_puesto_impresion"
        )
    with col2:
        filtro_turno = st.selectbox(
            "Filtrar por turno:",
            options=["Todos"] + sorted(df['turno_laboral'].unique()),
            key="filtro_turno_impresion"
        )

    # Aplicar filtros
    df_filtrado = df.copy()
    
    if filtro_puesto != "Todos":
        df_filtrado = df_filtrado[df_filtrado['puesto'] == filtro_puesto]
    
    if filtro_turno != "Todos":
        df_filtrado = df_filtrado[df_filtrado['turno_laboral'] == filtro_turno]

    if df_filtrado.empty:
        st.info("No hay usuarios que coincidan con los filtros aplicados")
        return

    # Opciones de formato
    formato = st.radio(
        "Formato de impresión:",
        ["Tabla resumen", "Listado detallado", "Formato PDF"],
        horizontal=True
    )

    if st.button("🖨️ Generar Reporte", type="primary"):
        if formato == "Tabla resumen":
            generar_tabla_resumen(df_filtrado)
        elif formato == "Listado detallado":
            generar_listado_detallado(df_filtrado)
        elif formato == "Formato PDF":
            generar_pdf(df_filtrado)

def generar_tabla_resumen(df):
    """Genera una tabla resumen de los usuarios"""
    st.subheader("📊 Tabla Resumen de Usuarios")
    
    # Mostrar estadísticas generales
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total de usuarios", len(df))
    with col2:
        st.metric("Puestos diferentes", df['puesto'].nunique())
    with col3:
        st.metric("Turnos diferentes", df['turno_laboral'].nunique())
    with col4:
        st.metric("Suplentes", len(df[df['suplencia'] == 'SI']))
    
    # Mostrar tabla
    columnas_a_mostrar = ['numero_economico', 'nombre_completo', 'puesto', 'servicio', 'turno_laboral', 'suplencia']
    df_display = df[columnas_a_mostrar].copy()
    
    st.dataframe(
        df_display,
        column_config={
            "numero_economico": "N° Económico",
            "nombre_completo": "Nombre",
            "puesto": "Puesto",
            "servicio": "Servicio",
            "turno_laboral": "Turno",
            "suplencia": "Suplencia"
        },
        hide_index=True,
        use_container_width=True
    )

def generar_listado_detallado(df):
    """Genera un listado detallado de los usuarios"""
    st.subheader("📋 Listado Detallado de Usuarios")
    
    for idx, usuario in df.iterrows():
        with st.expander(f"👤 {usuario['nombre_completo']} - {usuario['puesto']}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Número Económico:** {usuario['numero_economico']}")
                st.write(f"**Puesto:** {usuario['puesto']}")
                st.write(f"**Servicio:** {usuario['servicio']}")
                st.write(f"**Turno:** {usuario['turno_laboral']}")
            with col2:
                st.write(f"**Correo Electrónico:** {usuario.get('correo_electronico', 'No especificado')}")
                st.write(f"**Suplencia:** {usuario['suplencia']}")
                st.write(f"**N° Evento:** {usuario['numero_evento']}")
                st.write(f"**N° Consecutivo:** {usuario['numero_consecutivo']}")

def generar_pdf(df):
    """Genera un PDF con la información de los usuarios"""
    try:
        # Crear buffer para el PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Estilos
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        normal_style = styles['Normal']
        
        # Título
        title = Paragraph("Reporte de Usuarios - Archivo de Claves", title_style)
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Información del reporte
        fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        info_text = f"Generado el: {fecha} | Total de usuarios: {len(df)}"
        info_paragraph = Paragraph(info_text, normal_style)
        elements.append(info_paragraph)
        elements.append(Spacer(1, 12))
        
        # Preparar datos para la tabla
        data = [['N° Económico', 'Nombre', 'Puesto', 'Servicio', 'Turno', 'Suplencia']]
        
        for _, usuario in df.iterrows():
            data.append([
                usuario['numero_economico'],
                usuario['nombre_completo'],
                usuario['puesto'],
                usuario['servicio'],
                usuario['turno_laboral'],
                usuario['suplencia']
            ])
        
        # Crear tabla
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        
        # Construir PDF
        doc.build(elements)
        
        # Preparar para descarga
        buffer.seek(0)
        pdf_bytes = buffer.getvalue()
        
        # Crear botón de descarga
        st.success("✅ PDF generado correctamente")
        st.download_button(
            label="📥 Descargar PDF",
            data=pdf_bytes,
            file_name=f"reporte_usuarios_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            type="primary"
        )
        
    except Exception as e:
        st.error(f"❌ Error al generar PDF: {str(e)}")

# ====================
# FUNCIÓN PRINCIPAL
# ====================
def main():
    # Configuración de la página
    st.set_page_config(
        page_title="Sistema de Administración - Archivo de Claves",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Verificar autenticación
    authenticated, user_info = authenticate_user()
    
    if not authenticated:
        return

    # Mostrar información del usuario autenticado
    st.sidebar.title("👤 Información del Usuario")
    st.sidebar.write(f"**Número Económico:** {user_info['numero_economico']}")
    st.sidebar.write(f"**Nombre:** {user_info['nombre_completo']}")
    st.sidebar.write(f"**Puesto:** {user_info['puesto']}")
    if user_info.get('turno_laboral'):
        st.sidebar.write(f"**Turno:** {user_info['turno_laboral']}")

    # Opciones del menú principal
    st.sidebar.title("📋 Menú Principal")
    opcion = st.sidebar.radio(
        "Seleccione una operación:",
        [
            "📝 Creación de Usuarios",
            "✏️ Modificación de Usuarios", 
            "🗑️ Baja de Usuarios",
            "👥 Consulta de Usuarios",
            "🖨️ Impresión de Usuarios"
        ]
    )

    # Navegación entre opciones
    if opcion == "📝 Creación de Usuarios":
        mostrar_creacion_claves(user_info)
    elif opcion == "✏️ Modificación de Usuarios":
        mostrar_modificacion_claves(user_info)
    elif opcion == "🗑️ Baja de Usuarios":
        mostrar_baja_claves(user_info)
    elif opcion == "👥 Consulta de Usuarios":
        mostrar_consulta_claves(user_info)
    elif opcion == "🖨️ Impresión de Usuarios":
        mostrar_impresion_claves(user_info)

    # Información de debug en sidebar
    if CONFIG.DEBUG_MODE:
        st.sidebar.title("🐛 Debug Info")
        st.sidebar.write(f"Archivo de claves: {CONFIG.FILES['claves']}")
        st.sidebar.write(f"Archivo de asistencia: {CONFIG.FILES['asistencia']}")
        st.sidebar.write(f"Host: {CONFIG.REMOTE['HOST']}")
        st.sidebar.write(f"Directorio: {CONFIG.REMOTE['DIR']}")

    # Botón de cierre de sesión
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Cerrar Sesión", type="primary", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

if __name__ == "__main__":
    main()
