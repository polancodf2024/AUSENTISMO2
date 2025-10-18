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

def crear_archivo_asistencia(df_creacion):
    """
    Crea el archivo de asistencia a partir del archivo de creación de pacientes
    
    Args:
        df_creacion (DataFrame): DataFrame con los datos de creación de pacientes
    
    Returns:
        str: Ruta del archivo de asistencia creado
        DataFrame: DataFrame del archivo de asistencia
    """
    try:
        # Obtener la fecha y hora actual
        ahora = datetime.now()
        fecha_actual = ahora.strftime('%Y-%m-%d')
        hora_actual = ahora.strftime('%H:%M')
        fecha_hora_actual = ahora.strftime('%Y-%m-%d %H:%M')
        
        st.info(f"🕐 **Fecha y hora de registro:** {fecha_hora_actual}")
        
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
        
        # Nombre del archivo de asistencia usando variable de secrets.toml
        asistencia_filename = st.secrets["file_pacientes2"]
        
        # Guardar archivo de asistencia
        asistencia_df.to_csv(asistencia_filename, index=False, encoding='utf-8')
        
        st.success(f"✅ Archivo de asistencia creado: {asistencia_filename}")
        st.info(f"📊 Registros de asistencia generados: {len(asistencia_df)}")
        
        return asistencia_filename, asistencia_df
        
    except Exception as e:
        st.error(f"❌ Error creando archivo de asistencia: {str(e)}")
        import traceback
        st.error(f"🔍 Detalles del error: {traceback.format_exc()}")
        return None, None

def formatear_fecha_alta(fecha_alta):
    """
    Convierte una fecha de alta a formato YYYY-MM-DD
    
    Args:
        fecha_alta: Valor del campo fecha_alta (puede ser string, datetime, etc.)
    
    Returns:
        str: Fecha formateada en YYYY-MM-DD o cadena vacía si no es fecha válida
    """
    try:
        if pd.isna(fecha_alta) or fecha_alta == '' or str(fecha_alta).strip() == 'NaT':
            return ""
        
        # Si ya es un datetime, formatear directamente
        if isinstance(fecha_alta, (datetime, pd.Timestamp)):
            return fecha_alta.strftime('%Y-%m-%d')
        
        # Si es string, intentar parsear
        fecha_str = str(fecha_alta).strip()
        
        # Probar diferentes formatos de fecha
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
        
        # Si no se pudo parsear con formatos específicos, intentar con pandas
        try:
            fecha_dt = pd.to_datetime(fecha_str, errors='coerce')
            if not pd.isna(fecha_dt):
                return fecha_dt.strftime('%Y-%m-%d')
        except:
            pass
        
        return ""
        
    except Exception:
        return ""

def crear_archivo_historico(df_creacion):
    """
    Crea el archivo histórico con los pacientes que tienen fecha_alta = 'Alta'
    
    Args:
        df_creacion (DataFrame): DataFrame con los datos de creación de pacientes
    
    Returns:
        str: Ruta del archivo histórico creado
        DataFrame: DataFrame del archivo histórico
    """
    try:
        # Obtener la fecha y hora actual
        ahora = datetime.now()
        fecha_actual = ahora.strftime('%Y-%m-%d')
        hora_actual = ahora.strftime('%H:%M')
        fecha_hora_actual = ahora.strftime('%Y-%m-%d %H:%M')
        
        st.info(f"🕐 **Fecha y hora de registro histórico:** {fecha_hora_actual}")
        
        # Filtrar solo los pacientes con fecha_alta = 'Alta'
        df_altas = df_creacion[df_creacion['fecha_alta'] == 'Alta'].copy()
        
        if len(df_altas) == 0:
            st.info("ℹ️ **No hay pacientes con alta para agregar al histórico**")
            return None, None
        
        # Crear listas para cada columna del archivo histórico
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
        fechas_alta = []
        
        # Llenar las listas con los datos de los pacientes con alta
        for idx, row in df_altas.iterrows():
            fechas.append(fecha_hora_actual)
            fechas_turno.append(fecha_actual)
            expedientes.append(row['expediente'])
            nombres_completos.append(row['nombre_completo'])
            servicios.append(row['servicio'])
            turnos_laborales.append(row['turno_laboral'])
            
            # Usar la fecha_ingreso del archivo de creación para hora_entrada
            fecha_ingreso = row['fecha_ingreso']
            if isinstance(fecha_ingreso, str) and ' ' in fecha_ingreso:
                try:
                    hora_entrada_val = fecha_ingreso.split(' ')[1][:5]  # Tomar HH:MM
                    horas_entrada.append(hora_entrada_val)
                except:
                    horas_entrada.append(hora_actual)
            else:
                horas_entrada.append(hora_actual)
            
            incidencias.append("ALTA")  # Para pacientes con alta, la incidencia es "ALTA"
            edades.append(row['edad'])
            fechas_ingreso.append(row['fecha_ingreso'])
            diagnosticos.append(row['diagnostico'])
            numero_camas.append(row['numero_cama'])
            
            # MODIFICACIÓN: En lugar de "Alta", usar la fecha real en formato YYYY-MM-DD
            # Buscar la fecha original en el archivo Excel usando el campo temporal
            fecha_alta_original = row.get('_fecha_alta_original_temp', '')
            fecha_alta_formateada = formatear_fecha_alta(fecha_alta_original)
            fechas_alta.append(fecha_alta_formateada)
            
            # Mostrar información para los primeros 3 registros
            if idx < 3:
                st.write(f"🏥 **Registro {idx+1}:** Fecha Alta Original='{fecha_alta_original}' → fecha_alta='{fecha_alta_formateada}'")
        
        # Crear DataFrame para el archivo histórico
        historico_df = pd.DataFrame({
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
            'numero_cama': numero_camas,
            'fecha_alta': fechas_alta  # MODIFICADO: Ahora contiene la fecha formateada en lugar de "Alta"
        })
        
        # Asegurar tipos de datos compatibles
        historico_df = historico_df.astype({
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
            'numero_cama': 'int64',
            'fecha_alta': 'object'
        })
        
        # Nombre del archivo histórico usando variable de secrets.toml
        historico_filename = st.secrets["file_historico_pacientes2"]
        
        # Guardar archivo histórico
        historico_df.to_csv(historico_filename, index=False, encoding='utf-8')
        
        st.success(f"✅ Archivo histórico creado: {historico_filename}")
        st.info(f"📊 Registros históricos generados: {len(historico_df)}")
        
        # Mostrar estadísticas de fechas formateadas
        fechas_validas = sum(1 for fecha in fechas_alta if fecha != "")
        st.info(f"📅 Fechas de alta formateadas correctamente: {fechas_validas} de {len(fechas_alta)}")
        
        return historico_filename, historico_df
        
    except Exception as e:
        st.error(f"❌ Error creando archivo histórico: {str(e)}")
        import traceback
        st.error(f"🔍 Detalles del error: {traceback.format_exc()}")
        return None, None

def agregar_a_historico_pacientes(historico_filename):
    """
    ADICIONA los registros del archivo histórico local al archivo remoto aus_historico_pacientes2.csv
    
    Args:
        historico_filename (str): Ruta del archivo histórico local
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        # Obtener credenciales de secrets.toml
        remote_host = st.secrets["remote_host"]
        remote_user = st.secrets["remote_user"]
        remote_password = st.secrets["remote_password"]
        remote_port = st.secrets.get("remote_port", 22)
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
        
        # Ruta completa del archivo remoto usando variable de secrets.toml
        remote_filename = st.secrets["file_historico_pacientes2"]
        remote_path = f"{remote_dir}/{remote_filename}"
        
        # Leer el archivo histórico local
        df_nuevo_historico = pd.read_csv(historico_filename)
        
        # Leer archivo histórico remoto existente (si existe)
        try:
            with sftp_client.file(remote_path, 'r') as archivo_remoto:
                contenido_existente = archivo_remoto.read().decode('utf-8')
            
            if contenido_existente.strip():
                # Si ya existe contenido, leer el DataFrame existente
                df_existente = pd.read_csv(StringIO(contenido_existente))
                
                # ADICIONAR los nuevos registros a los existentes
                df_completo = pd.concat([df_existente, df_nuevo_historico], ignore_index=True)
                
                st.info(f"📚 **Registros existentes en histórico:** {len(df_existente)}")
                st.info(f"📝 **Nuevos registros a adicionar:** {len(df_nuevo_historico)}")
                st.info(f"📊 **Total después de adición:** {len(df_completo)}")
            else:
                # Si no existe contenido, usar solo el nuevo
                df_completo = df_nuevo_historico
                st.info(f"📝 **Nuevos registros a crear:** {len(df_completo)}")
                
        except FileNotFoundError:
            # Si el archivo remoto no existe, crear uno nuevo
            df_completo = df_nuevo_historico
            st.info(f"📝 **Creando nuevo archivo histórico con:** {len(df_completo)} registros")
        
        # Guardar el archivo completo en el servidor remoto
        with sftp_client.file(remote_path, 'w') as archivo_remoto:
            archivo_remoto.write(df_completo.to_csv(index=False, encoding='utf-8'))
        
        # Cerrar conexiones
        sftp_client.close()
        ssh_client.close()
        
        st.success(f"✅ Registros ADICIONADOS exitosamente a {remote_filename}")
        return True
        
    except Exception as e:
        st.error(f"❌ Error al ADICIONAR registros a {st.secrets['file_historico_pacientes2']}: {str(e)}")
        try:
            sftp_client.close()
        except:
            pass
        try:
            ssh_client.close()
        except:
            pass
        return False

def excel_to_csv(excel_file, csv_file=None, sheet_name=0, fecha_nac_col=None):
    """
    Convierte un archivo Excel a CSV con layout específico
    
    Args:
        excel_file: Archivo Excel subido o ruta del archivo
        csv_file (str, optional): Ruta del archivo CSV de salida
        sheet_name (str/int): Nombre o índice de la hoja a convertir
        fecha_nac_col (str): Nombre específico de la columna de fecha de nacimiento
    """
    try:
        # Leer el archivo Excel
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        
        # Obtener el nombre original del archivo para determinar el servicio
        if hasattr(excel_file, 'name'):
            original_filename = excel_file.name
        else:
            original_filename = str(excel_file)
        
        # Determinar el servicio basado en el nombre del archivo
        if "CORO" in original_filename.upper():
            servicio = "Unidad-Coronaria"
            csv_filename = "censo_Unidad-Coronaria.csv"
        else:
            servicio = "Consulta-Externa"
            # Usar el nombre original cambiando la extensión
            csv_filename = original_filename.replace('.xlsx', '.csv').replace('.xls', '.csv')
        
        # Si se proporciona un nombre específico para el CSV, usarlo
        if csv_file is not None:
            csv_filename = csv_file
        
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
        
        # Nombre completo
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
        
        # Llenar las listas con los datos mapeados
        for idx, row in df.iterrows():
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
            
            # Nombre completo
            if column_mapping['nombre_completo'] is not None:
                nombre_val = row[column_mapping['nombre_completo']]
                if pd.isna(nombre_val) or nombre_val == '':
                    nombres_completos.append("Pendiente")
                else:
                    nombres_completos.append(str(nombre_val).upper())
            else:
                nombres_completos.append("Pendiente")
            
            # Servicio (siempre del nombre del archivo)
            servicios.append(servicio)
            
            # Edad (calculada desde fecha de nacimiento)
            if column_mapping['fecha_nacimiento'] is not None:
                fecha_nac = row[column_mapping['fecha_nacimiento']]
                edad_calculada = calcular_edad(fecha_nac)
                edades.append(edad_calculada)
                
                # Mostrar cálculo para los primeros 3 registros
                if idx < 3:
                    st.write(f"🎂 **Registro {idx+1}:** Fecha Nac='{fecha_nac}' → Edad={edad_calculada}")
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
                    
                    # Mostrar información para los primeros 3 registros
                    if idx < 3:
                        st.write(f"🏥 **Registro {idx+1}:** Fecha Alta='{fecha_alta_val}' → fecha_alta='Alta'")
                else:
                    # Si está vacío, poner cadena vacía
                    fechas_alta.append("")
                    # Mostrar información para los primeros 3 registros
                    if idx < 3:
                        st.write(f"🏥 **Registro {idx+1}:** Fecha Alta='{fecha_alta_val}' → fecha_alta=''")
            else:
                # Si no existe la columna Fch Alta, poner cadena vacía para todos
                fechas_alta.append("")
                fechas_alta_originales_temp.append("")
        
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
        
        st.success(f"✅ **Archivo convertido exitosamente:** {csv_filename}")
        st.info(f"📊 **Total de registros convertidos:** {len(layout_df)}")
        
        # Mostrar estadísticas de altas
        total_altas = sum(1 for x in fechas_alta if x == "Alta")
        st.info(f"🏥 **Pacientes con alta:** {total_altas}")
        
        return csv_filename, layout_df
        
    except Exception as e:
        st.error(f"❌ **Error en la conversión:** {str(e)}")
        import traceback
        st.error(f"🔍 **Detalles del error:** {traceback.format_exc()}")
        return None, None

def main():
    st.title("🏥 Sistema de Gestión de Ausentismo - Pacientes")
    
    # Configuración de la página
    st.set_page_config(
        page_title="Sistema Ausentismo Pacientes",
        page_icon="🏥",
        layout="wide"
    )
    
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
    
    # Tabs principales
    tab1, tab2, tab3, tab4 = st.tabs([
        "📤 Subir y Convertir Excel", 
        "📊 Generar Asistencia", 
        "📚 Gestión Histórica",
        "ℹ️ Información del Sistema"
    ])
    
    with tab1:
        st.header("📤 Subir y Convertir Archivo Excel")
        
        # Sección para subir archivo Excel
        uploaded_file = st.file_uploader(
            "Selecciona el archivo Excel de pacientes", 
            type=['xlsx', 'xls'],
            help="Sube el archivo Excel con los datos de los pacientes"
        )
        
        if uploaded_file is not None:
            # Mostrar información del archivo
            file_details = {
                "Nombre": uploaded_file.name,
                "Tipo": uploaded_file.type,
                "Tamaño": f"{uploaded_file.size / 1024:.2f} KB"
            }
            st.write("📄 **Detalles del archivo:**")
            st.json(file_details)
            
            # Opción para especificar manualmente la columna de fecha de nacimiento
            st.subheader("🔧 Configuración de Conversión")
            
            # Leer el archivo para obtener nombres de columnas
            try:
                df_preview = pd.read_excel(uploaded_file, nrows=1)
                columnas_disponibles = df_preview.columns.tolist()
                
                col1, col2 = st.columns(2)
                
                with col1:
                    fecha_nac_col = st.selectbox(
                        "Selecciona la columna de FECHA DE NACIMIENTO:",
                        options=[""] + columnas_disponibles,
                        help="Si no seleccionas ninguna, se intentará detectar automáticamente"
                    )
                
                with col2:
                    sheet_name = st.text_input(
                        "Nombre de la hoja (opcional):",
                        value="",
                        help="Deja vacío para usar la primera hoja"
                    )
                
            except Exception as e:
                st.error(f"❌ Error leyendo el archivo Excel: {str(e)}")
                fecha_nac_col = ""
                sheet_name = ""
            
            # Botón para convertir
            if st.button("🔄 Convertir Excel a CSV", type="primary"):
                with st.spinner("Convirtiendo archivo Excel a CSV..."):
                    try:
                        # Reiniciar el puntero del archivo
                        uploaded_file.seek(0)
                        
                        # Convertir Excel a CSV usando variable de secrets.toml
                        csv_filename = st.secrets["file_creacion_pacientes2"]
                        
                        # Usar sheet_name si se especificó, sino usar 0 (primera hoja)
                        sheet_to_use = sheet_name if sheet_name else 0
                        
                        csv_path, df_resultado = excel_to_csv(
                            uploaded_file, 
                            csv_filename, 
                            sheet_name=sheet_to_use,
                            fecha_nac_col=fecha_nac_col if fecha_nac_col else None
                        )
                        
                        if csv_path and df_resultado is not None:
                            st.success("✅ **Conversión completada exitosamente!**")
                            
                            # Mostrar vista previa del CSV generado
                            st.subheader("👀 Vista Previa del Archivo CSV Generado")
                            st.dataframe(df_resultado.head(10), use_container_width=True)
                            
                            # Mostrar estadísticas
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Registros", len(df_resultado))
                            with col2:
                                st.metric("Servicio", df_resultado['servicio'].iloc[0] if len(df_resultado) > 0 else "N/A")
                            with col3:
                                altas_count = len(df_resultado[df_resultado['fecha_alta'] == 'Alta'])
                                st.metric("Pacientes con Alta", altas_count)
                            
                            # Opción para subir automáticamente al servidor remoto
                            if st.button("☁️ Subir CSV al Servidor Remoto", type="secondary"):
                                with st.spinner("Subiendo archivo al servidor remoto..."):
                                    remote_path, success = upload_to_remote(csv_path, csv_filename)
                                    if success:
                                        st.success(f"✅ **Archivo subido exitosamente a:** {remote_path}")
                                    else:
                                        st.error("❌ **Error al subir el archivo al servidor remoto**")
                            
                            # Descargar archivo CSV localmente
                            with open(csv_path, 'rb') as f:
                                csv_data = f.read()
                            
                            st.download_button(
                                label="📥 Descargar CSV Localmente",
                                data=csv_data,
                                file_name=csv_filename,
                                mime="text/csv",
                                help="Descarga el archivo CSV generado a tu dispositivo"
                            )
                            
                        else:
                            st.error("❌ **Error en la conversión del archivo**")
                            
                    except Exception as e:
                        st.error(f"❌ **Error durante la conversión:** {str(e)}")
                        if debug_mode:
                            import traceback
                            st.error(f"🔍 **Detalles del error:** {traceback.format_exc()}")
    
    with tab2:
        st.header("📊 Generar Archivo de Asistencia")
        
        # Opción para usar archivo local o descargar del servidor
        fuente_archivo = st.radio(
            "Selecciona la fuente del archivo de creación:",
            ["📁 Usar archivo local", "☁️ Descargar del servidor remoto"],
            horizontal=True
        )
        
        archivo_creacion_path = None
        df_creacion = None
        
        if fuente_archivo == "📁 Usar archivo local":
            # Buscar archivo local usando variable de secrets.toml
            archivo_creacion_local = st.secrets["file_creacion_pacientes2"]
            if os.path.exists(archivo_creacion_local):
                archivo_creacion_path = archivo_creacion_local
                df_creacion = pd.read_csv(archivo_creacion_path)
                st.success(f"✅ **Archivo local encontrado:** {archivo_creacion_local}")
            else:
                st.warning(f"⚠️ **No se encontró el archivo local:** {archivo_creacion_local}")
        
        else:  # Descargar del servidor remoto
            if st.button("⬇️ Descargar Archivo del Servidor Remoto", type="primary"):
                with st.spinner("Descargando archivo del servidor remoto..."):
                    # Usar variable de secrets.toml para el nombre del archivo
                    remote_filename = st.secrets["file_creacion_pacientes2"]
                    local_path, success = download_from_remote(remote_filename)
                    
                    if success:
                        archivo_creacion_path = local_path
                        df_creacion = pd.read_csv(archivo_creacion_path)
                        st.success(f"✅ **Archivo descargado exitosamente:** {remote_filename}")
                    else:
                        st.error(f"❌ **Error al descargar el archivo:** {remote_filename}")
        
        # Si tenemos datos de creación, mostrar información y opciones
        if df_creacion is not None:
            st.subheader("📋 Información del Archivo de Creación")
            
            # Mostrar estadísticas
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Pacientes", len(df_creacion))
            with col2:
                servicio_principal = df_creacion['servicio'].mode()[0] if len(df_creacion) > 0 else "N/A"
                st.metric("Servicio Principal", servicio_principal)
            with col3:
                pacientes_altas = len(df_creacion[df_creacion['fecha_alta'] == 'Alta'])
                st.metric("Pacientes con Alta", pacientes_altas)
            with col4:
                pacientes_activos = len(df_creacion) - pacientes_altas
                st.metric("Pacientes Activos", pacientes_activos)
            
            # Mostrar vista previa
            st.dataframe(df_creacion.head(), use_container_width=True)
            
            # Botón para generar archivo de asistencia
            if st.button("🔄 Generar Archivo de Asistencia", type="primary"):
                with st.spinner("Generando archivo de asistencia..."):
                    asistencia_path, df_asistencia = crear_archivo_asistencia(df_creacion)
                    
                    if asistencia_path and df_asistencia is not None:
                        st.success("✅ **Archivo de asistencia generado exitosamente!**")
                        
                        # Mostrar vista previa del archivo de asistencia
                        st.subheader("👀 Vista Previa del Archivo de Asistencia")
                        st.dataframe(df_asistencia.head(), use_container_width=True)
                        
                        # Opción para subir automáticamente al servidor remoto
                        if st.button("☁️ Subir Asistencia al Servidor Remoto", type="secondary"):
                            with st.spinner("Subiendo archivo de asistencia al servidor remoto..."):
                                # Usar variable de secrets.toml para el nombre del archivo
                                remote_filename = st.secrets["file_pacientes2"]
                                remote_path, success = upload_to_remote(asistencia_path, remote_filename)
                                if success:
                                    st.success(f"✅ **Archivo de asistencia subido exitosamente a:** {remote_path}")
                                else:
                                    st.error("❌ **Error al subir el archivo de asistencia al servidor remoto**")
                        
                        # Descargar archivo de asistencia localmente
                        with open(asistencia_path, 'rb') as f:
                            asistencia_data = f.read()
                        
                        st.download_button(
                            label="📥 Descargar Asistencia Localmente",
                            data=asistencia_data,
                            file_name=os.path.basename(asistencia_path),
                            mime="text/csv",
                            help="Descarga el archivo de asistencia generado a tu dispositivo"
                        )
        
        else:
            st.info("ℹ️ **Carga o descarga un archivo de creación de pacientes para generar la asistencia**")
    
    with tab3:
        st.header("📚 Gestión de Archivo Histórico")
        
        # Verificar si tenemos datos de creación
        if df_creacion is not None:
            # Contar pacientes con alta
            pacientes_con_alta = len(df_creacion[df_creacion['fecha_alta'] == 'Alta'])
            
            st.subheader("📊 Estadísticas de Altas")
            st.info(f"🏥 **Pacientes listos para mover al histórico:** {pacientes_con_alta}")
            
            if pacientes_con_alta > 0:
                # Mostrar pacientes que serán movidos al histórico
                st.subheader("👥 Pacientes con Alta para Mover al Histórico")
                df_altas = df_creacion[df_creacion['fecha_alta'] == 'Alta'].copy()
                st.dataframe(df_altas[['expediente', 'nombre_completo', 'servicio', 'fecha_ingreso']], use_container_width=True)
                
                # Botón para generar archivo histórico
                if st.button("📚 Generar Archivo Histórico", type="primary"):
                    with st.spinner("Generando archivo histórico..."):
                        historico_path, df_historico = crear_archivo_historico(df_creacion)
                        
                        if historico_path and df_historico is not None:
                            st.success("✅ **Archivo histórico generado exitosamente!**")
                            
                            # Mostrar vista previa del archivo histórico
                            st.subheader("👀 Vista Previa del Archivo Histórico")
                            st.dataframe(df_historico.head(), use_container_width=True)
                            
                            # Botón para ADICIONAR al histórico remoto
                            if st.button("🔄 ADICIONAR al Histórico Remoto", type="secondary"):
                                with st.spinner("Adicionando registros al histórico remoto..."):
                                    success = agregar_a_historico_pacientes(historico_path)
                                    if success:
                                        st.success("✅ **Registros ADICIONADOS exitosamente al archivo histórico remoto!**")
                                        
                                        # Mostrar resumen de la operación
                                        st.subheader("📋 Resumen de la Operación")
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.metric("Registros Adicionados", len(df_historico))
                                        with col2:
                                            st.metric("Operación", "ADICIÓN")
                                        
                                        # Opción para limpiar el archivo de creación local
                                        if st.checkbox("🗑️ Limpiar pacientes con alta del archivo de creación local"):
                                            # Filtrar solo pacientes sin alta
                                            df_creacion_sin_altas = df_creacion[df_creacion['fecha_alta'] != 'Alta'].copy()
                                            
                                            # Guardar el archivo actualizado
                                            archivo_creacion_local = st.secrets["file_creacion_pacientes2"]
                                            df_creacion_sin_altas.to_csv(archivo_creacion_local, index=False)
                                            
                                            st.success(f"✅ **Archivo de creación actualizado:** {len(df_creacion_sin_altas)} pacientes activos")
                                            
                                            # Actualizar el DataFrame en memoria
                                            df_creacion = df_creacion_sin_altas
                                            
                                            # Mostrar nuevo conteo
                                            st.info(f"📊 **Nuevo total de pacientes activos:** {len(df_creacion_sin_altas)}")
                                    else:
                                        st.error("❌ **Error al adicionar registros al histórico remoto**")
                            
                            # Descargar archivo histórico localmente
                            with open(historico_path, 'rb') as f:
                                historico_data = f.read()
                            
                            st.download_button(
                                label="📥 Descargar Histórico Localmente",
                                data=historico_data,
                                file_name=os.path.basename(historico_path),
                                mime="text/csv",
                                help="Descarga el archivo histórico generado a tu dispositivo"
                            )
            else:
                st.info("ℹ️ **No hay pacientes con alta para mover al histórico**")
        else:
            st.info("ℹ️ **Carga o descarga un archivo de creación de pacientes para gestionar el histórico**")
    
    with tab4:
        st.header("ℹ️ Información del Sistema")
        
        st.subheader("📁 Archivos de Configuración")
        
        # Mostrar configuración actual (sin contraseñas)
        config_info = {
            "Servidor SMTP": st.secrets["smtp_server"],
            "Puerto SMTP": st.secrets["smtp_port"],
            "Usuario Email": st.secrets["email_user"],
            "Email Notificación": st.secrets["notification_email"],
            "Servidor Remoto": st.secrets["remote_host"],
            "Usuario Remoto": st.secrets["remote_user"],
            "Puerto Remoto": st.secrets["remote_port"],
            "Directorio Remoto": st.secrets["remote_dir"],
            "Modo Supervisor": st.secrets["supervisor_mode"],
            "Modo Debug": st.secrets["debug_mode"]
        }
        
        st.json(config_info)
        
        st.subheader("📊 Archivos del Sistema")
        
        archivos_sistema = {
            "Creación de Pacientes": st.secrets["file_creacion_pacientes2"],
            "Asistencia de Pacientes": st.secrets["file_pacientes2"],
            "Histórico de Pacientes": st.secrets["file_historico_pacientes2"],
            "Eventos Adversos": st.secrets["file_eventos2"],
            "Suplencias Activas": st.secrets["file_suplencias2"]
        }
        
        st.json(archivos_sistema)
        
        st.subheader("🔧 Funcionalidades")
        
        funcionalidades = [
            "✅ Conversión de Excel a CSV con mapeo automático de columnas",
            "✅ Cálculo automático de edad desde fecha de nacimiento",
            "✅ Detección automática de pacientes con alta",
            "✅ Generación de archivos de asistencia",
            "✅ Gestión de archivo histórico con adición de registros",
            "✅ Transferencia segura SFTP a servidor remoto",
            "✅ Soporte para múltiples formatos de fecha",
            "✅ Modo supervisor para operaciones avanzadas",
            "✅ Modo debug para troubleshooting"
        ]
        
        for func in funcionalidades:
            st.write(func)
        
        # Información de conexión remota
        st.subheader("🌐 Estado de Conexión")
        
        if st.button("🔍 Probar Conexión al Servidor Remoto"):
            with st.spinner("Probando conexión al servidor remoto..."):
                try:
                    # Obtener credenciales de secrets.toml
                    remote_host = st.secrets["remote_host"]
                    remote_user = st.secrets["remote_user"]
                    remote_password = st.secrets["remote_password"]
                    remote_port = st.secrets.get("remote_port")
                    
                    # Crear cliente SSH
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Conectar al servidor
                    ssh_client.connect(
                        hostname=remote_host,
                        username=remote_user,
                        password=remote_password,
                        port=remote_port,
                        timeout=10
                    )
                    
                    # Ejecutar comando simple
                    stdin, stdout, stderr = ssh_client.exec_command('pwd')
                    working_dir = stdout.read().decode().strip()
                    
                    # Cerrar conexión
                    ssh_client.close()
                    
                    st.success(f"✅ **Conexión exitosa!** Directorio actual: {working_dir}")
                    
                except Exception as e:
                    st.error(f"❌ **Error de conexión:** {str(e)}")

if __name__ == "__main__":
    main()
