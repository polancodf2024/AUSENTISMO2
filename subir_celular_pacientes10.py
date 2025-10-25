import pandas as pd
import streamlit as st
import os
from datetime import datetime
import numpy as np
import paramiko
from io import StringIO
import tempfile

def upload_to_remote(local_file_path, remote_filename):
    """
    Sube un archivo al servidor remoto usando SFTP
    
    Args:
        local_file_path (str): Ruta local del archivo
        remote_filename (str): Nombre del archivo remoto
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port") 
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Cambiar al directorio remoto
        try:
            sftp_client.chdir(remote_dir)
        except:
            st.warning(f"⚠️ No se pudo cambiar al directorio {remote_dir}, usando directorio por defecto")
        
        # Subir archivo
        remote_path = f"{remote_dir}/{remote_filename}"
        sftp_client.put(local_file_path, remote_path)
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        st.success(f"✅ Archivo subido exitosamente a: {remote_path}")
        return remote_path, True
        
    except Exception as e:
        st.error(f"❌ Error subiendo archivo al servidor remoto: {str(e)}")
        return None, False

def download_from_remote(remote_filename, local_filename=None):
    """
    Descarga un archivo del servidor remoto usando SFTP
    
    Args:
        remote_filename (str): Nombre del archivo remoto
        local_filename (str): Nombre del archivo local (opcional)
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Crear archivo temporal local si no se proporciona nombre
        if local_filename is None:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
            local_path = temp_file.name
            temp_file.close()
        else:
            local_path = local_filename
        
        # Descargar archivo
        sftp_client.get(remote_path, local_path)
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        st.success(f"✅ Archivo descargado exitosamente de: {remote_path}")
        return local_path, True
        
    except Exception as e:
        st.error(f"❌ Error descargando archivo del servidor remoto: {str(e)}")
        return None, False

def leer_archivo_remoto(remote_filename):
    """
    Lee un archivo CSV del servidor remoto y lo convierte a DataFrame
    sin descargarlo localmente
    
    Args:
        remote_filename (str): Nombre del archivo remoto
    
    Returns:
        DataFrame: DataFrame con los datos del archivo remoto
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Leer archivo remoto directamente a memoria
        with sftp_client.file(remote_path, 'r') as remote_file:
            contenido = remote_file.read().decode('utf-8')
        
        # Convertir a DataFrame
        df = pd.read_csv(StringIO(contenido))
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return df, True
        
    except Exception as e:
        st.error(f"❌ Error leyendo archivo remoto {remote_filename}: {str(e)}")
        return None, False

def guardar_archivo_remoto(df, remote_filename):
    """
    Guarda un DataFrame directamente en el servidor remoto
    sin crear archivo local
    
    Args:
        df (DataFrame): DataFrame a guardar
        remote_filename (str): Nombre del archivo remoto
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Convertir DataFrame a CSV en memoria
        csv_data = df.to_csv(index=False, encoding='utf-8')
        
        # Guardar directamente en el servidor remoto
        with sftp_client.file(remote_path, 'w') as remote_file:
            remote_file.write(csv_data)
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error guardando archivo remoto {remote_filename}: {str(e)}")
        return False

def listar_archivos_remotos(patron):
    """
    Lista archivos en el servidor remoto que coincidan con un patrón
    
    Args:
        patron (str): Patrón de búsqueda (ej: "input_*.csv")
    
    Returns:
        list: Lista de nombres de archivos que coinciden
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Cambiar al directorio remoto
        try:
            sftp_client.chdir(remote_dir)
        except:
            st.warning(f"⚠️ No se pudo cambiar al directorio {remote_dir}")
            return []
        
        # Listar archivos
        archivos = sftp_client.listdir()
        
        # Filtrar archivos por patrón
        archivos_filtrados = [archivo for archivo in archivos if patron in archivo]
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return archivos_filtrados
        
    except Exception as e:
        st.error(f"❌ Error listando archivos remotos: {str(e)}")
        return []

def borrar_archivo_remoto(remote_filename):
    """
    Borra un archivo del servidor remoto
    
    Args:
        remote_filename (str): Nombre del archivo remoto a borrar
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Borrar archivo
        sftp_client.remove(remote_path)
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error borrando archivo remoto {remote_filename}: {str(e)}")
        return False

def limpiar_contenido_archivo_remoto(remote_filename):
    """
    Limpia el contenido de un archivo remoto, dejando solo los encabezados
    
    Args:
        remote_filename (str): Nombre del archivo remoto
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Leer el archivo para obtener los encabezados
        try:
            with sftp_client.file(remote_path, 'r') as remote_file:
                contenido = remote_file.read().decode('utf-8')
            
            # Obtener la primera línea (encabezados)
            lineas = contenido.split('\n')
            if lineas:
                encabezados = lineas[0]
                
                # Guardar solo los encabezados
                with sftp_client.file(remote_path, 'w') as remote_file:
                    remote_file.write(encabezados)
                
            else:
                # Si el archivo está vacío, crear encabezados básicos
                encabezados_basicos = "expediente,numero_cama,nombre_completo,servicio,edad,diagnostico,fecha_ingreso,turno_laboral,fecha_alta,_fecha_alta_original_temp\n"
                with sftp_client.file(remote_path, 'w') as remote_file:
                    remote_file.write(encabezados_basicos)
                
        except FileNotFoundError:
            # Si el archivo no existe, crear uno con encabezados básicos
            encabezados_basicos = "expediente,numero_cama,nombre_completo,servicio,edad,diagnostico,fecha_ingreso,turno_laboral,fecha_alta,_fecha_alta_original_temp\n"
            with sftp_client.file(remote_path, 'w') as remote_file:
                remote_file.write(encabezados_basicos)
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error limpiando archivo remoto {remote_filename}: {str(e)}")
        return False

def adicionar_a_archivo_historico(df_nuevo, archivo_historico, tipo_historico):
    """
    ADICIONA registros a un archivo histórico remoto
    
    Args:
        df_nuevo (DataFrame): DataFrame con los nuevos registros
        archivo_historico (str): Nombre del archivo histórico
        tipo_historico (str): Tipo de histórico ('creacion' o 'asistencia')
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{archivo_historico}"
        
        # Leer archivo histórico remoto existente (si existe)
        try:
            with sftp_client.file(remote_path, 'r') as archivo_remoto:
                contenido_existente = archivo_remoto.read().decode('utf-8')
            
            if contenido_existente.strip():
                # Si ya existe contenido, leer el DataFrame existente
                df_existente = pd.read_csv(StringIO(contenido_existente))
                
                # ADICIONAR los nuevos registros a los existentes
                df_completo = pd.concat([df_existente, df_nuevo], ignore_index=True)
                
            else:
                # Si no existe contenido, usar solo el nuevo
                df_completo = df_nuevo
                
        except FileNotFoundError:
            # Si el archivo remoto no existe, crear uno nuevo
            df_completo = df_nuevo
        
        # Guardar el archivo completo en el servidor remoto
        with sftp_client.file(remote_path, 'w') as archivo_remoto:
            archivo_remoto.write(df_completo.to_csv(index=False, encoding='utf-8'))
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error al ADICIONAR registros a {archivo_historico}: {str(e)}")
        try:
            sftp_client.close()
        except:
            pass
        try:
            ssh_client.close()
        except:
            pass
        return False

def adicionar_a_archivo_principal(df_nuevo, archivo_principal, tipo_archivo):
    """
    ADICIONA registros a un archivo principal remoto (creación o asistencia)
    
    Args:
        df_nuevo (DataFrame): DataFrame con los nuevos registros
        archivo_principal (str): Nombre del archivo principal
        tipo_archivo (str): Tipo de archivo ('creacion' o 'asistencia')
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port")
        remote_dir = st.secrets["remote_dir"]
        
        # Crear cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=remote_host,
            username=remote_user,
            password=remote_password,
            port=remote_port
        )
        
        # Crear cliente SFTP
        sftp_client = ssh_client.open_sftp()
        
        # Ruta completa del archivo remoto
        remote_path = f"{remote_dir}/{archivo_principal}"
        
        # Leer archivo principal remoto existente (si existe)
        try:
            with sftp_client.file(remote_path, 'r') as archivo_remoto:
                contenido_existente = archivo_remoto.read().decode('utf-8')
            
            if contenido_existente.strip():
                # Si ya existe contenido, leer el DataFrame existente
                df_existente = pd.read_csv(StringIO(contenido_existente))
                
                # ADICIONAR los nuevos registros a los existentes
                df_completo = pd.concat([df_existente, df_nuevo], ignore_index=True)
                
            else:
                # Si no existe contenido, usar solo el nuevo
                df_completo = df_nuevo
                
        except FileNotFoundError:
            # Si el archivo remoto no existe, crear uno nuevo
            df_completo = df_nuevo
        
        # Guardar el archivo completo en el servidor remoto
        with sftp_client.file(remote_path, 'w') as archivo_remoto:
            archivo_remoto.write(df_completo.to_csv(index=False, encoding='utf-8'))
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error al ADICIONAR registros a {archivo_principal}: {str(e)}")
        try:
            sftp_client.close()
        except:
            pass
        try:
            ssh_client.close()
        except:
            pass
        return False

def proceso_inicio_sesion():
    """
    Ejecuta el proceso automático al iniciar sesión:
    1. Borrar archivos input_*.csv
    2. Adicionar registros de creación al histórico
    3. Adicionar registros de asistencia al histórico
    4. Limpiar archivos principales
    """
    try:
        st.info("🔄 **Ejecutando proceso automático de inicio de sesión...**")
        
        # Obtener nombres de archivos desde secrets.toml
        file_creacion_pacientes2 = st.secrets["file_creacion_pacientes2"]
        file_asistencia_pacientes2 = st.secrets["file_asistencia_pacientes2"]
        file_historico_creacion_pacientes2 = st.secrets["file_historico_creacion_pacientes2"]
        file_historico_asistencia_pacientes2 = st.secrets["file_historico_asistencia_pacientes2"]
        
        # 1. BORRAR ARCHIVOS INPUT
        st.subheader("🧹 Paso 1: Limpieza de archivos input")
        archivos_input = listar_archivos_remotos("input_")
        
        if archivos_input:
            st.info(f"📁 **Archivos input encontrados:** {len(archivos_input)}")
            for archivo in archivos_input:
                st.write(f"   - {archivo}")
            
            # Borrar archivos input
            for archivo in archivos_input:
                if borrar_archivo_remoto(archivo):
                    st.success(f"✅ Borrado: {archivo}")
                else:
                    st.error(f"❌ Error borrando: {archivo}")
                    return False
        else:
            st.info("ℹ️ No se encontraron archivos input para borrar")
        
        # 2. RESPALDO HISTÓRICO - Adicionar a archivos históricos
        st.subheader("📚 Paso 2: Respaldo histórico")
        
        # 2.1 Respaldo de creación
        df_creacion_actual, success = leer_archivo_remoto(file_creacion_pacientes2)
        if success and df_creacion_actual is not None and len(df_creacion_actual) > 0:
            st.info(f"📊 **Registros actuales en creación:** {len(df_creacion_actual)}")
            success = adicionar_a_archivo_historico(
                df_creacion_actual, 
                file_historico_creacion_pacientes2, 
                "creación"
            )
            if success:
                st.success("✅ Registros de creación adicionados al histórico")
            else:
                st.error("❌ Error adicionando registros de creación al histórico")
                return False
        else:
            st.info("ℹ️ No hay registros actuales en creación para respaldar")
        
        # 2.2 Respaldo de asistencia
        df_asistencia_actual, success = leer_archivo_remoto(file_asistencia_pacientes2)
        if success and df_asistencia_actual is not None and len(df_asistencia_actual) > 0:
            st.info(f"📊 **Registros actuales en asistencia:** {len(df_asistencia_actual)}")
            success = adicionar_a_archivo_historico(
                df_asistencia_actual, 
                file_historico_asistencia_pacientes2, 
                "asistencia"
            )
            if success:
                st.success("✅ Registros de asistencia adicionados al histórico")
            else:
                st.error("❌ Error adicionando registros de asistencia al histórico")
                return False
        else:
            st.info("ℹ️ No hay registros actuales en asistencia para respaldar")
        
        # 3. LIMPIEZA FINAL - Limpiar archivos principales
        st.subheader("🧹 Paso 3: Limpieza de archivos principales")
        
        # 3.1 Limpiar archivo de creación
        if limpiar_contenido_archivo_remoto(file_creacion_pacientes2):
            st.success("✅ Archivo de creación limpiado exitosamente")
        else:
            st.error("❌ Error limpiando archivo de creación")
            return False
        
        # 3.2 Limpiar archivo de asistencia
        if limpiar_contenido_archivo_remoto(file_asistencia_pacientes2):
            st.success("✅ Archivo de asistencia limpiado exitosamente")
        else:
            st.error("❌ Error limpiando archivo de asistencia")
            return False
        
        st.success("🎉 **PROCESO DE INICIO DE SESIÓN COMPLETADO EXITOSAMENTE**")
        st.info("💡 **El sistema está listo para recibir nuevos registros**")
        
        return True
        
    except Exception as e:
        st.error(f"❌ Error en el proceso de inicio de sesión: {str(e)}")
        import traceback
        st.error(f"🔍 Detalles del error: {traceback.format_exc()}")
        return False

def formatear_fecha_alta(fecha_alta):
    """
    Convierte una fecha de alta a formato YYYY-MM-DD
    """
    try:
        if pd.isna(fecha_alta) or fecha_alta == '' or str(fecha_alta).strip() == 'NaT':
            return ""
        
        if isinstance(fecha_alta, (datetime, pd.Timestamp)):
            return fecha_alta.strftime('%Y-%m-%d')
        
        fecha_str = str(fecha_alta).strip()
        formatos = [
            '%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%Y/%m/%d',
            '%d-%m-%Y', '%m-%d-%Y', '%d.%m.%Y', '%m.%d.%Y',
            '%d/%m/%y', '%m/%d/%y', '%d-%m-%y', '%y-%m-%d'
        ]
        
        for formato in formatos:
            try:
                fecha_dt = datetime.strptime(fecha_str, formato)
                return fecha_dt.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        try:
            fecha_dt = pd.to_datetime(fecha_str, errors='coerce')
            if not pd.isna(fecha_dt):
                return fecha_dt.strftime('%Y-%m-%d')
        except:
            pass
        
        return ""
        
    except Exception:
        return ""

def excel_to_csv(excel_file, csv_file=None, sheet_name=0, fecha_nac_col=None, servicio_nombre=None):
    """
    Convierte un archivo Excel a CSV con layout específico
    """
    try:
        # Leer el archivo Excel
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        
        # Si se proporciona un nombre específico para el CSV, usarlo
        if csv_file is not None:
            csv_filename = csv_file
        else:
            # Generar nombre basado en el servicio
            nombre_servicio_simple = servicio_nombre.replace(' ', '_').replace('/', '_').replace('\\', '_')
            csv_filename = f"input_{nombre_servicio_simple}.csv"
        
        # Mostrar información de columnas para debugging
        st.info(f"🔍 **Todas las columnas detectadas en el Excel:**")
        for i, col in enumerate(df.columns):
            st.write(f"   {i+1}. **{col}** (tipo: {df[col].dtype})")
        
        # Buscar columnas en el DataFrame original
        column_mapping = {}
        
        # Expediente
        expediente_cols = [col for col in df.columns if 'expediente' in str(col).lower() or 'exp' in str(col).lower()]
        column_mapping['expediente'] = expediente_cols[0] if expediente_cols else None
        
        # Número cama
        cama_cols = [col for col in df.columns if 'cama' in str(col).lower() or 'cama' in str(col).lower()]
        column_mapping['numero_cama'] = cama_cols[0] if cama_cols else None
        
        # Nombre completo - BUSCAR COLUMNA PACIENTE
        nombre_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['nombre', 'paciente', 'name', 'nom'])]
        column_mapping['nombre_completo'] = nombre_cols[0] if nombre_cols else None
        
        # Fecha de nacimiento - PRIORIDAD: usar columna especificada manualmente
        if fecha_nac_col and fecha_nac_col in df.columns:
            column_mapping['fecha_nacimiento'] = fecha_nac_col
            st.success(f"✅ **Usando columna especificada para fecha de nacimiento:** {fecha_nac_col}")
        else:
            # Búsqueda automática más agresiva
            fecha_nac_cols = []
            for col in df.columns:
                col_lower = str(col).lower().replace(' ', '').replace('_', '').replace('-', '')
                if any(x in col_lower for x in ['fechanac', 'fchnac', 'nacimiento', 'fnac', 'f.nac', 'fechanacim', 'fechadenac']):
                    fecha_nac_cols.append(col)
                elif 'nac' in col_lower and any(x in col_lower for x in ['fecha', 'fec']):
                    fecha_nac_cols.append(col)
                # Buscar por patrones comunes en español
                elif any(x in str(col).lower() for x in ['fecha de nac', 'fecha nacimiento', 'fch nac']):
                    fecha_nac_cols.append(col)
            
            column_mapping['fecha_nacimiento'] = fecha_nac_cols[0] if fecha_nac_cols else None
            
            if column_mapping['fecha_nacimiento']:
                st.success(f"✅ **Campo de fecha de nacimiento detectado automáticamente:** {column_mapping['fecha_nacimiento']}")
            else:
                st.warning("⚠️ **No se detectó campo de fecha de nacimiento automáticamente.**")
        
        # Mostrar valores de ejemplo de la columna de fecha de nacimiento
        if column_mapping['fecha_nacimiento']:
            sample_values = df[column_mapping['fecha_nacimiento']].head(5).tolist()
            st.write(f"📅 **Valores de ejemplo de fecha de nacimiento:**")
            for i, val in enumerate(sample_values):
                st.write(f"   {i+1}. {val} (tipo: {type(val).__name__})")
        
        # Diagnóstico
        diag_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['diagnostico', 'diagnóstico', 'dx', 'diag'])]
        column_mapping['diagnostico'] = diag_cols[0] if diag_cols else None
        
        # Fecha ingreso
        fecha_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['fecha', 'ingreso', 'admission', 'fecing', 'fecha_ing'])]
        column_mapping['fecha_ingreso'] = fecha_cols[0] if fecha_cols else None
        
        # Buscar columna "Fch Alta" (columna I o por nombre)
        fch_alta_col = None
        # Primero buscar por nombre exacto "Fch Alta"
        if 'Fch Alta' in df.columns:
            fch_alta_col = 'Fch Alta'
            st.success(f"✅ **Columna 'Fch Alta' detectada:** Se agregará campo 'fecha_alta' al CSV")
        # Si no existe, buscar por posición (columna I - índice 8)
        elif len(df.columns) > 8:
            fch_alta_col = df.columns[8]
            st.info(f"ℹ️ **Usando columna en posición I (índice 8):** {fch_alta_col} para fecha de alta")
        else:
            st.warning("⚠️ **No se encontró columna 'Fch Alta' en posición I (índice 8)**")
        
        # Mostrar valores de ejemplo de la columna de fecha de alta si existe
        if fch_alta_col:
            sample_values_alta = df[fch_alta_col].head(5).tolist()
            st.write(f"📅 **Valores de ejemplo de fecha de alta ({fch_alta_col}):**")
            for i, val in enumerate(sample_values_alta):
                st.write(f"   {i+1}. {val} (tipo: {type(val).__name__})")
        
        # Función mejorada para calcular edad desde fecha de nacimiento
        def calcular_edad(fecha_nac):
            try:
                if pd.isna(fecha_nac) or fecha_nac == '' or fecha_nac is None:
                    return 0
                
                # Si ya es un datetime, usarlo directamente
                if isinstance(fecha_nac, (pd.Timestamp, datetime)):
                    fecha_nac_dt = fecha_nac
                else:
                    # Intentar convertir string a datetime
                    fecha_nac_str = str(fecha_nac).strip()
                    
                    # Probar diferentes formatos de fecha
                    formatos = ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y', '%Y/%m/%d',
                               '%d/%m/%y', '%m/%d/%y', '%d-%m-%y', '%Y%m%d', '%d.%m.%Y', '%m.%d.%Y']
                    
                    fecha_nac_dt = None
                    for formato in formatos:
                        try:
                            fecha_nac_dt = datetime.strptime(fecha_nac_str, formato)
                            break
                        except:
                            continue
                    
                    if fecha_nac_dt is None:
                        # Intentar parsear con pandas
                        try:
                            fecha_nac_dt = pd.to_datetime(fecha_nac_str, errors='coerce')
                            if pd.isna(fecha_nac_dt):
                                return 0
                        except:
                            return 0
                
                hoy = datetime.now()
                edad = hoy.year - fecha_nac_dt.year
                
                # Ajustar si aún no ha pasado el cumpleaños este año
                if (hoy.month, hoy.day) < (fecha_nac_dt.month, fecha_nac_dt.day):
                    edad -= 1
                
                return max(0, edad)  # Asegurar que no sea negativo
                
            except Exception as e:
                st.warning(f"⚠️ Error calculando edad para fecha '{fecha_nac}': {str(e)}")
                return 0
        
        # Crear listas para cada columna (más eficiente que concatenar DataFrames)
        expedientes = []
        numero_camas = []
        nombres_completos = []
        servicios = []
        edades = []
        diagnosticos = []
        fechas_ingreso = []
        turnos_laborales = []
        fechas_alta = []  # Lista para el campo fecha_alta (solo "Alta" o vacío)
        fechas_alta_originales_temp = []  # CORRECCIÓN: Lista temporal para guardar fecha original solo para uso interno
        
        # Contadores para estadísticas
        total_registros = 0
        registros_omitidos = 0
        registros_procesados = 0
        
        # Llenar las listas con los datos mapeados - FILTRANDO REGISTROS SIN PACIENTE
        for idx, row in df.iterrows():
            total_registros += 1
            
            # VERIFICAR SI LA COLUMNA PACIENTE ESTÁ VACÍA
            if column_mapping['nombre_completo'] is not None:
                nombre_val = row[column_mapping['nombre_completo']]
                # Si el nombre está vacío, NaN, o es una cadena vacía, omitir este registro
                if pd.isna(nombre_val) or nombre_val == '' or str(nombre_val).strip() == '':
                    registros_omitidos += 1
                    continue  # Saltar este registro y pasar al siguiente
            
            registros_procesados += 1
            
            # Expediente
            if column_mapping['expediente'] is not None:
                expediente_val = row[column_mapping['expediente']]
                if pd.isna(expediente_val) or expediente_val == '':
                    expedientes.append(f"EXP{10000 + idx}")
                else:
                    expedientes.append(str(expediente_val))
            else:
                expedientes.append(f"EXP{10000 + idx}")
            
            # Número cama
            if column_mapping['numero_cama'] is not None:
                cama_val = row[column_mapping['numero_cama']]
                if pd.isna(cama_val) or cama_val == '':
                    numero_camas.append(200 + idx)
                else:
                    # Convertir a int si es posible
                    try:
                        numero_camas.append(int(float(cama_val)))
                    except:
                        numero_camas.append(200 + idx)
            else:
                numero_camas.append(200 + idx)
            
            # Nombre completo (ya verificado que no está vacío)
            if column_mapping['nombre_completo'] is not None:
                nombre_val = row[column_mapping['nombre_completo']]
                nombres_completos.append(str(nombre_val).upper())
            else:
                nombres_completos.append("Pendiente")
            
            # Servicio (usar el nombre proporcionado)
            servicios.append(servicio_nombre)
            
            # Edad (calculada desde fecha de nacimiento)
            if column_mapping['fecha_nacimiento'] is not None:
                fecha_nac = row[column_mapping['fecha_nacimiento']]
                edad_calculada = calcular_edad(fecha_nac)
                edades.append(edad_calculada)
            else:
                edades.append(0)
            
            # Diagnóstico
            if column_mapping['diagnostico'] is not None:
                diag_val = row[column_mapping['diagnostico']]
                if pd.isna(diag_val) or diag_val == '':
                    diagnosticos.append("Pendiente")
                else:
                    diagnosticos.append(str(diag_val))
            else:
                diagnosticos.append("Pendiente")
            
            # Fecha ingreso
            if column_mapping['fecha_ingreso'] is not None:
                fecha_ingreso = row[column_mapping['fecha_ingreso']]
                # Formatear fecha si es datetime
                if hasattr(fecha_ingreso, 'strftime'):
                    fechas_ingreso.append(fecha_ingreso.strftime('%Y-%m-%d'))
                else:
                    fechas_ingreso.append(str(fecha_ingreso))
            else:
                fechas_ingreso.append("2025-09-24")
            
            # Turno laboral (siempre el mismo)
            turnos_laborales.append("Estancia Corta (0:00 - 24:00)")
            
            # Fecha de alta - NUEVO CAMPO
            if fch_alta_col is not None:
                fecha_alta_val = row[fch_alta_col]
                # CORRECCIÓN: Guardar la fecha original solo en lista temporal para uso interno
                fechas_alta_originales_temp.append(fecha_alta_val)
                
                # Verificar si la fecha de alta tiene un valor válido (no está vacío, no es NaN, etc.)
                if pd.notna(fecha_alta_val) and fecha_alta_val != '' and str(fecha_alta_val).strip() != 'NaT':
                    # Si tiene una fecha válida, poner "Alta" en el archivo de creación
                    fechas_alta.append("Alta")
                else:
                    # Si está vacío, poner cadena vacía
                    fechas_alta.append("")
            else:
                # Si no existe la columna Fch Alta, poner cadena vacía para todos
                fechas_alta.append("")
                fechas_alta_originales_temp.append("")
        
        # Mostrar estadísticas de filtrado
        st.info(f"📊 **Estadísticas de conversión:**")
        st.info(f"   • Total de registros en Excel: {total_registros}")
        st.info(f"   • Registros omitidos (sin paciente): {registros_omitidos}")
        st.info(f"   • Registros procesados: {registros_procesados}")
        
        if registros_omitidos > 0:
            st.warning(f"⚠️ Se omitieron {registros_omitidos} registros porque la columna 'Paciente' estaba vacía")
        
        # Verificar si hay registros para procesar
        if registros_procesados == 0:
            st.error("❌ No hay registros válidos para convertir. Todos los registros tienen la columna 'Paciente' vacía.")
            return None, None
        
        # Crear DataFrame final con tipos de datos explícitos y compatibles
        layout_data = {
            'expediente': expedientes,
            'numero_cama': numero_camas,
            'nombre_completo': nombres_completos,
            'servicio': servicios,
            'edad': edades,
            'diagnostico': diagnosticos,
            'fecha_ingreso': fechas_ingreso,
            'turno_laboral': turnos_laborales,
            'fecha_alta': fechas_alta  # CORRECCIÓN: Solo el campo fecha_alta normal
        }
        
        layout_df = pd.DataFrame(layout_data)
        
        # CORRECCIÓN: Agregar la fecha original como campo temporal interno (no se guarda en CSV)
        # Esto es solo para uso en la función crear_archivo_historico
        layout_df['_fecha_alta_original_temp'] = fechas_alta_originales_temp
        
        # Asegurar tipos de datos compatibles con Streamlit
        # Usar object en lugar de string para mejor compatibilidad
        layout_df = layout_df.astype({
            'expediente': 'object',
            'numero_cama': 'int64',
            'nombre_completo': 'object',
            'servicio': 'object',
            'edad': 'int64',
            'diagnostico': 'object',
            'fecha_ingreso': 'object',
            'turno_laboral': 'object',
            'fecha_alta': 'object',
            '_fecha_alta_original_temp': 'object'  # Campo temporal interno
        })
        
        # Guardar como CSV
        layout_df.to_csv(csv_filename, index=False, encoding='utf-8')
        
        # Mostrar estadísticas
        st.success(f"✅ **Archivo CSV creado exitosamente:** {csv_filename}")
        st.info(f"📊 **Total de registros convertidos:** {len(layout_df)}")
        st.info(f"🏥 **Servicio asignado:** {servicio_nombre}")
        
        # Mostrar estadísticas de altas
        total_altas = sum(1 for x in fechas_alta if x == "Alta")
        st.info(f"📅 **Pacientes con alta:** {total_altas} de {len(fechas_alta)}")
        
        # Mostrar vista previa del DataFrame
        st.subheader("📋 **Vista previa del archivo CSV creado**")
        st.dataframe(layout_df.drop(columns=['_fecha_alta_original_temp']).head(10))  # Ocultar campo temporal en vista previa
        
        return csv_filename, layout_df
        
    except Exception as e:
        st.error(f"❌ Error convirtiendo Excel a CSV: {str(e)}")
        import traceback
        st.error(f"🔍 Detalles del error: {traceback.format_exc()}")
        return None, None

def crear_archivo_asistencia_desde_input(servicio_nombre):
    """
    Crea el archivo de asistencia a partir del archivo input del servicio
    y lo ADICIONA al archivo principal de asistencia
    """
    try:
        # Obtener la fecha y hora actual
        ahora = datetime.now()
        fecha_actual = ahora.strftime('%Y-%m-%d')
        hora_actual = ahora.strftime('%H:%M')
        fecha_hora_actual = ahora.strftime('%Y-%m-%d %H:%M')
        
        st.info(f"🕐 **Fecha y hora de registro:** {fecha_hora_actual}")
        
        # Leer archivo input del servicio desde el servidor remoto
        nombre_servicio_simple = servicio_nombre.replace(' ', '_').replace('/', '_').replace('\\', '_')
        input_filename = f"input_{nombre_servicio_simple}.csv"
        
        df_creacion, success = leer_archivo_remoto(input_filename)
        if not success or df_creacion is None:
            st.error(f"❌ No se pudo leer el archivo remoto: {input_filename}")
            return False
        
        # Crear listas para cada columna del archivo de asistencia
        fechas = []
        fechas_turno = []
        expedientes = []
        nombres_completos = []
        servicios = []
        turnos_laborales = []
        horas_entrada = []
        incidencias = []
        edades = []
        fechas_ingreso = []
        diagnosticos = []
        numero_camas = []
        
        # Llenar las listas con los datos del archivo de creación
        for idx, row in df_creacion.iterrows():
            # Solo procesar pacientes que NO tengan fecha de alta
            if 'fecha_alta' in row and row['fecha_alta'] == 'Alta':
                continue  # Saltar pacientes con alta
            
            fechas.append(fecha_hora_actual)
            fechas_turno.append(fecha_actual)
            expedientes.append(row['expediente'])
            nombres_completos.append(row['nombre_completo'])
            servicios.append(row['servicio'])
            
            # Usar el turno_laboral del archivo de creación
            turnos_laborales.append(row['turno_laboral'])
            
            # Usar la fecha_ingreso del archivo de creación para hora_entrada
            # Extraer solo la parte de la hora si es una fecha completa, sino usar hora actual
            fecha_ingreso = row['fecha_ingreso']
            if isinstance(fecha_ingreso, str) and ' ' in fecha_ingreso:
                # Si tiene espacio, probablemente es fecha y hora
                try:
                    hora_entrada_val = fecha_ingreso.split(' ')[1][:5]  # Tomar HH:MM
                    horas_entrada.append(hora_entrada_val)
                except:
                    horas_entrada.append(hora_actual)
            else:
                # Si no tiene hora, usar la hora actual
                horas_entrada.append(hora_actual)
            
            incidencias.append("NO")  # Siempre "NO" por defecto
            edades.append(row['edad'])
            fechas_ingreso.append(row['fecha_ingreso'])
            diagnosticos.append(row['diagnostico'])
            numero_camas.append(row['numero_cama'])
        
        # Crear DataFrame para el archivo de asistencia
        asistencia_df = pd.DataFrame({
            'fecha': fechas,
            'fecha_turno': fechas_turno,
            'expediente': expedientes,
            'nombre_completo': nombres_completos,
            'servicio': servicios,
            'turno_laboral': turnos_laborales,
            'hora_entrada': horas_entrada,
            'incidencias': incidencias,
            'edad': edades,
            'fecha_ingreso': fechas_ingreso,
            'diagnostico': diagnosticos,
            'numero_cama': numero_camas
        })
        
        # Asegurar tipos de datos compatibles
        asistencia_df = asistencia_df.astype({
            'fecha': 'object',
            'fecha_turno': 'object',
            'expediente': 'object',
            'nombre_completo': 'object',
            'servicio': 'object',
            'turno_laboral': 'object',
            'hora_entrada': 'object',
            'incidencias': 'object',
            'edad': 'int64',
            'fecha_ingreso': 'object',
            'diagnostico': 'object',
            'numero_cama': 'int64'
        })
        
        # ADICIONAR al archivo principal de asistencia
        success = adicionar_a_archivo_principal(
            asistencia_df, 
            st.secrets["file_asistencia_pacientes2"], 
            "asistencia"
        )
        
        if success:
            st.success(f"✅ Registros de asistencia ADICIONADOS exitosamente para {servicio_nombre}")
            st.info(f"📊 Registros de asistencia generados: {len(asistencia_df)}")
            return True
        else:
            st.error(f"❌ Error adicionando registros de asistencia para {servicio_nombre}")
            return False
        
    except Exception as e:
        st.error(f"❌ Error creando archivo de asistencia: {str(e)}")
        import traceback
        st.error(f"🔍 Detalles del error: {traceback.format_exc()}")
        return False

def main():
#    st.title("🏥 Sistema de Gestión de Ausentismo - Pacientes")
    
    # Configuración de la página
    st.set_page_config(
        page_title="Sistema Ausentismo Pacientes",
        page_icon="🏥",
        layout="wide"
    )
    
    # Sistema de autenticación
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.proceso_inicio_ejecutado = False
    
    if not st.session_state.authenticated:
        st.title("🏥 Sistema de Gestión de Ausentismo - Pacientes")
        st.markdown("---")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.subheader("🔐 Iniciar Sesión")
            
            login = st.text_input("👤 Usuario", placeholder="Ingrese su usuario")
            password = st.text_input("🔒 Contraseña", type="password", placeholder="Ingrese su contraseña")
            
            if st.button("🚀 Ingresar al Sistema", type="primary", use_container_width=True):
                if login == "administracion" and password == "gabylira2026":
                    st.session_state.authenticated = True
                    st.success("✅ ¡Autenticación exitosa!")
                    st.info("🔄 Ejecutando proceso automático de inicio de sesión...")
                    
                    # Ejecutar proceso automático de inicio de sesión
                    with st.spinner("Procesando..."):
                        success = proceso_inicio_sesion()
                        if success:
                            st.session_state.proceso_inicio_ejecutado = True
                            st.rerun()
                        else:
                            st.error("❌ Error en el proceso automático. Contacte al administrador.")
                            st.session_state.authenticated = False
                else:
                    st.error("❌ Usuario o contraseña incorrectos")
        
        return
    
    # Si está autenticado, mostrar la aplicación completa
    
    # Lista exacta de los 19 servicios del archivo Excel (solo los 11 primeros)
    servicios = [
        "UNIDAD CORONARIA",
        "CARDIOLOGÍA ADULTOS III",
        "CARDIONEUMOLOGÍA",
        "NEFROLOGÍA",
        "HEMODINÁMICA",
        "TERAPIA INTENSIVA CARDIOVASCULAR",
        "QUIRÓFANO",
        "CARDIOLOGÍA PEDIÁTRICA",
        "CARDIOLOGÍA ADULTOS VII",
        "HOSPITALIZACIÓN OCTAVO PISO",
        "HOSPITALIZACIÓN NOVENO PISO"
    ]
    
    # Sidebar para configuración
    st.sidebar.header("⚙️ Configuración")
    
    # Opción para modo supervisor
    supervisor_mode = st.secrets.get("supervisor_mode", False)
    if supervisor_mode:
        st.sidebar.info("🔒 **Modo Supervisor Activado**")
    
    # Opción para modo debug
    debug_mode = st.secrets.get("debug_mode", False)
    if debug_mode:
        st.sidebar.warning("🐛 **Modo Debug Activado**")
    
    # Botón de cierre de sesión
    if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.proceso_inicio_ejecutado = False
        st.rerun()
    
    # Tabs principales - SOLO 2 PESTAÑAS (sin Información del Sistema)
    tab1, tab2 = st.tabs([
        "📤 Subir Archivos por Servicio", 
        "📊 Generar Archivos del Sistema"
    ])
    
    with tab1:
        st.header("📤 Subir Archivos por Servicio")
        st.info("💡 **Cada servicio tiene su propio uploader. Sube archivos Excel que se convertirán automáticamente a CSV y se subirán al servidor remoto.**")
        
        # Crear uploaders independientes organizados en 3 columnas
        st.subheader("📁 Uploaders por Servicio")
        
        # Dividir en 3 columnas para mejor organización
        col1, col2, col3 = st.columns(3)
        
        uploaded_files = {}
        
        with col1:
            for i in range(0, 4):  # Primeros 4 servicios
                servicio = servicios[i]
                nombre_servicio_simple = servicio.replace(' ', '_').replace('/', '_').replace('\\', '_')
                
                st.markdown(f"**{servicio}**")
                uploaded_file = st.file_uploader(
                    f"Subir Excel para {servicio}",
                    type=['xlsx', 'xls'],
                    key=f"upload_{i}",
                    help=f"Se guardará como: input_{nombre_servicio_simple}.csv"
                )
                if uploaded_file:
                    uploaded_files[servicio] = uploaded_file
                    st.success(f"✅ {uploaded_file.name}")
        
        with col2:
            for i in range(4, 8):  # Siguientes 4 servicios
                servicio = servicios[i]
                nombre_servicio_simple = servicio.replace(' ', '_').replace('/', '_').replace('\\', '_')
                
                st.markdown(f"**{servicio}**")
                uploaded_file = st.file_uploader(
                    f"Subir Excel para {servicio}",
                    type=['xlsx', 'xls'],
                    key=f"upload_{i}",
                    help=f"Se guardará como: input_{nombre_servicio_simple}.csv"
                )
                if uploaded_file:
                    uploaded_files[servicio] = uploaded_file
                    st.success(f"✅ {uploaded_file.name}")
        
        with col3:
            for i in range(8, 11):  # Últimos 3 servicios
                servicio = servicios[i]
                nombre_servicio_simple = servicio.replace(' ', '_').replace('/', '_').replace('\\', '_')
                
                st.markdown(f"**{servicio}**")
                uploaded_file = st.file_uploader(
                    f"Subir Excel para {servicio}",
                    type=['xlsx', 'xls'],
                    key=f"upload_{i}",
                    help=f"Se guardará como: input_{nombre_servicio_simple}.csv"
                )
                if uploaded_file:
                    uploaded_files[servicio] = uploaded_file
                    st.success(f"✅ {uploaded_file.name}")
        
        # Botón para procesar todos los archivos subidos
        if uploaded_files:
            st.subheader("🔄 Procesar Archivos Subidos")
            
            if st.button("🚀 Procesar Todos los Archivos", type="primary", key="procesar_todos"):
                resultados = []
                
                for servicio, uploaded_file in uploaded_files.items():
                    with st.spinner(f"Procesando {servicio}..."):
                        try:
                            nombre_servicio_simple = servicio.replace(' ', '_').replace('/', '_').replace('\\', '_')
                            csv_filename = f"input_{nombre_servicio_simple}.csv"
                            
                            # Convertir Excel a CSV
                            csv_path, df_resultado = excel_to_csv(
                                uploaded_file,
                                csv_filename,
                                servicio_nombre=servicio
                            )
                            
                            if csv_path and df_resultado is not None:
                                # Subir al servidor remoto
                                remote_path, success = upload_to_remote(csv_path, csv_filename)
                                
                                if success:
                                    resultados.append({
                                        'servicio': servicio,
                                        'archivo': uploaded_file.name,
                                        'registros': len(df_resultado),
                                        'estado': '✅ Éxito',
                                        'ruta_remota': remote_path
                                    })
                                else:
                                    resultados.append({
                                        'servicio': servicio,
                                        'archivo': uploaded_file.name,
                                        'registros': 0,
                                        'estado': '❌ Error subida',
                                        'ruta_remota': 'N/A'
                                    })
                            else:
                                resultados.append({
                                    'servicio': servicio,
                                    'archivo': uploaded_file.name,
                                    'registros': 0,
                                    'estado': '❌ Error conversión',
                                    'ruta_remota': 'N/A'
                                })
                                
                        except Exception as e:
                            resultados.append({
                                'servicio': servicio,
                                'archivo': uploaded_file.name,
                                'registros': 0,
                                'estado': f'❌ Error: {str(e)}',
                                'ruta_remota': 'N/A'
                            })
                
                # Mostrar resumen de resultados
                st.subheader("📊 Resumen de Procesamiento")
                df_resultados = pd.DataFrame(resultados)
                st.dataframe(df_resultados, use_container_width=True)
                
                # Estadísticas
                exitosos = sum(1 for r in resultados if '✅' in r['estado'])
                st.info(f"**Procesamiento completado:** {exitosos} de {len(resultados)} archivos procesados exitosamente")
        
        else:
            st.info("ℹ️ **Sube archivos Excel en los uploaders de arriba para comenzar el procesamiento**")
    
    with tab2:
        st.header("📊 Generar Archivos del Sistema")
        st.info("💡 **Genera los archivos principales del sistema directamente en el servidor remoto**")
        
        # Selección de servicio para procesar
        servicio_seleccionado = st.selectbox(
            "Selecciona el servicio para generar archivos:",
            servicios,
            key="servicio_generar_tab3"
        )
        
        # Botones para generar archivos directamente en el servidor remoto
        st.subheader("🔄 Generar Archivos en Servidor Remoto")
        
        col_gen1, col_gen2 = st.columns(2)
        
        with col_gen1:
            if st.button("📄 ADICIONAR a creacion_pacientes2", type="primary", key="adicionar_creacion", use_container_width=True):
                with st.spinner("Adicionando registros a creación..."):
                    # Leer archivo input
                    nombre_servicio_simple = servicio_seleccionado.replace(' ', '_').replace('/', '_').replace('\\', '_')
                    input_filename = f"input_{nombre_servicio_simple}.csv"
                    
                    df_creacion, success = leer_archivo_remoto(input_filename)
                    if success and df_creacion is not None:
                        success = adicionar_a_archivo_principal(
                            df_creacion, 
                            st.secrets["file_creacion_pacientes2"], 
                            "creación"
                        )
                        if success:
                            st.success("✅ **Registros ADICIONADOS exitosamente a creación!**")
                    else:
                        st.error(f"❌ No se pudo leer el archivo: {input_filename}")
        
        with col_gen2:
            if st.button("📊 ADICIONAR a asistencia_pacientes2", type="primary", key="adicionar_asistencia", use_container_width=True):
                with st.spinner("Adicionando registros a asistencia..."):
                    success = crear_archivo_asistencia_desde_input(servicio_seleccionado)
                    if success:
                        st.success("✅ **Registros ADICIONADOS exitosamente a asistencia!**")

if __name__ == "__main__":
    main()
