from pymongo import MongoClient
import json
import re
from tqdm import tqdm
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
import ipaddress
from functools import lru_cache

class DataIntegrator:
    def __init__(self, num_threads=8):
        self.region_dict = {}
        self.attacks_dict = {}
        self.ip_network_cache = {}
        self.num_threads = num_threads
        self.results_queue = queue.Queue()
        self.data_queue = queue.Queue()
        self.lock = threading.Lock()
        
    def connect_to_mongodb(self):
        """Establece conexión con MongoDB"""
        try:
            client = MongoClient('mongodb+srv://smoscoso:Sergio_M10S@cluster0.v6amn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/')
            client.server_info()
            return client['Logs']
        except Exception as e:
            print(f"Error connecting to MongoDB: {e}")
            return None

    def load_json_file(self, filename):
        """Carga el archivo JSON"""
        try:
            print(f"Cargando archivo JSON: {filename}")
            with open(filename, 'r', encoding='utf-8') as file:
                data = json.load(file)
                if not isinstance(data, list):
                    data = [data]
                return data[:5000]  # Limitar a 5000 IPs
        except Exception as e:
            print(f"Error al cargar el archivo JSON: {e}")
            return None

    def precompile_patterns(self, db):
        """Precompila patrones regex y optimiza búsquedas"""
        print("Precargando patrones...")
        
        # Cargar regiones usando threads
        def load_regions(region_docs):
            local_cache = {}
            local_patterns = {}
            for doc in region_docs:
                try:
                    network = ipaddress.ip_network(doc['ip'].replace('*', '0/24'), strict=False)
                    local_cache[network] = doc['region']
                except ValueError:
                    ip_pattern = re.escape(doc['ip']).replace('\\*', '.*')
                    local_patterns[re.compile(f"^{ip_pattern}$")] = doc['region']
            return local_cache, local_patterns

        # Cargar attacks usando threads
        def load_attacks(attack_docs):
            local_dict = {}
            for doc in attack_docs:
                local_dict[doc['resource']] = doc['status']  # No incluir el campo 'status'
            return local_dict

        # Dividir documentos en chunks para procesamiento paralelo
        regions = list(db.Region.find())
        attacks = list(db.Attacks.find())
        
        chunk_size = max(1, len(regions) // self.num_threads)
        region_chunks = [regions[i:i + chunk_size] for i in range(0, len(regions), chunk_size)]
        
        # Procesar regiones en paralelo
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            region_futures = [executor.submit(load_regions, chunk) for chunk in region_chunks]
            
            for future in as_completed(region_futures):
                cache, patterns = future.result()
                with self.lock:
                    self.ip_network_cache.update(cache)
                    self.region_dict.update(patterns)
        
        # Procesar attacks en paralelo
        chunk_size = max(1, len(attacks) // self.num_threads)
        attack_chunks = [attacks[i:i + chunk_size] for i in range(0, len(attacks), chunk_size)]
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            attack_futures = [executor.submit(load_attacks, chunk) for chunk in attack_chunks]
            
            for future in as_completed(attack_futures):
                with self.lock:
                    self.attacks_dict.update(future.result())

    @lru_cache(maxsize=1024)
    def find_ip_region(self, ip):
        """Busca la región de una IP con caché"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for network, region in self.ip_network_cache.items():
                if ip_addr in network:
                    return region
        except ValueError:
            pass

        for pattern, region in self.region_dict.items():
            if pattern.match(ip):
                return region
        return 'Unknown'

    def process_records(self):
        while True:
            try:
                batch = self.data_queue.get_nowait()
                if batch is None:
                    break
                
                results = []
                for entry in batch:
                    new_entry = entry.copy()  # Copia todo el diccionario original
                    new_entry['region'] = self.find_ip_region(entry.get('ip', ''))
                    new_entry['resource_found'] = self.attacks_dict.get(entry.get('resource', ''), False)
                    results.append(new_entry)
                
                self.results_queue.put(results)
            except queue.Empty:
                break
            finally:
                self.data_queue.task_done()

    def integrate_data(self, json_filename, output_filename):
        """Integra los datos usando múltiples threads"""
        print(" Iniciando integración de datos con procesamiento multi-hilo...")
        start_time = time.time()
        
        # Conectar a MongoDB
        db = self.connect_to_mongodb()
        if db is None:
            return

        # Cargar datos JSON
        data = self.load_json_file(json_filename)
        if data is None:
            return

        # Precompilar patrones
        self.precompile_patterns(db)

        # Dividir datos en batches
        batch_size = 1000
        batches = [data[i:i + batch_size] for i in range(0, len(data), batch_size)]
        total_batches = len(batches)

        print(f"\n Procesando {len(data)} registros usando {self.num_threads} threads...")
        
        # Poner batches en la cola
        for batch in batches:
            self.data_queue.put(batch)
        
        # Agregar marcadores de fin para cada thread
        for _ in range(self.num_threads):
            self.data_queue.put(None)

        # Crear y empezar threads
        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.process_records)
            t.start()
            threads.append(t)

        # Procesar resultados mientras los threads trabajan
        processed_data = []
        with tqdm(total=len(data), desc="Progreso") as pbar:
            completed_batches = 0
            while completed_batches < total_batches:
                try:
                    results = self.results_queue.get(timeout=1)
                    processed_data.extend(results)
                    pbar.update(len(results))
                    completed_batches += 1
                except queue.Empty:
                    continue

        # Esperar a que todos los threads terminen
        for t in threads:
            t.join()

        # Guardar resultados sin modificar la estructura original
        print("\n  Guardando resultados...")
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, indent=4)
            print(f" Datos guardados exitosamente en {output_filename}")
        except Exception as e:
            print(f" Error al guardar datos: {e}")

        end_time = time.time()
        duration = end_time - start_time
        records_per_second = len(data) / duration
        print(f"\n  Proceso completado en {duration:.2f} segundos")
        print(f"  Velocidad de procesamiento: {records_per_second:.2f} registros/segundo")

def main():
    # Obtener el número de threads óptimo (número de núcleos * 2)
    import multiprocessing
    optimal_threads = multiprocessing.cpu_count() * 2
    
    print(f"  Iniciando proceso con {optimal_threads} threads...")
    
    integrator = DataIntegrator(num_threads=optimal_threads)
    integrator.integrate_data('dataCollected.json', 'integrated.json')

if __name__ == "__main__":
    main()