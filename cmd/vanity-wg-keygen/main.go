package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var workers []*Worker

type keypair struct {
	publicKey  string
	privateKey string
}

func main() {
	threads := flag.Int("threads", runtime.NumCPU(), "threads")
	flag.Parse()
	var findString = flag.Args()[0]
	var outDir = "./"

	results := make(chan keypair)
	lm := LowercasePrefixMatcher{findString}
	for i := 0; i < *threads; i++ {
		w := &Worker{
			Count:        0,
			Matcher:      lm,
			KeyGenerator: NewKeypair,
		}
		workers = append(workers, w)
		go w.findKey(results)
	}

	// Log stats during execution
	start := time.Now()
	ticker := time.NewTicker(time.Second * 2)
	go func() {
		for range ticker.C {
			printStats(start)
		}
	}()

	result := <-results

	ticker.Stop()
	printStats(start)

	log.Println("Found pubkey:")
	log.Print(string(result.publicKey))

	_ = ioutil.WriteFile(outDir+findString, []byte(result.publicKey), 0600)
	_ = ioutil.WriteFile(outDir+findString+".pub", []byte(result.privateKey), 0644)
}

func printStats(start time.Time) {
	sum := totalCount()
	elapsed := time.Since(start)
	log.Println("Time:", elapsed.Truncate(time.Second).String())
	log.Println("Tested:", sum)
	log.Println(fmt.Sprintf("%.2f", sum/elapsed.Seconds()/1000), "kKeys/s")
}

func totalCount() float64 {
	var sum float64
	for _, w := range workers {
		sum += float64(w.Count)
	}
	return sum
}

type Matcher interface {
	Match(keypair) bool
}

type LowercaseMatcher struct {
	matchString string
}

func (m LowercaseMatcher) Match(s keypair) bool {
	return strings.Contains(strings.ToLower(s.publicKey), m.matchString)
}

type LowercasePrefixMatcher struct {
	matchString string
}

func (m LowercasePrefixMatcher) Match(s keypair) bool {
	return strings.HasPrefix(strings.ToLower(s.publicKey), m.matchString)
}

type Worker struct {
	Count uint64
	Matcher
	KeyGenerator func() keypair
}

func (w *Worker) findKey(result chan keypair) {
	var err error
	var k keypair
	for {
		w.Count += 1
		k = w.KeyGenerator()
		if err != nil {
			log.Println(err)
			return
		}
		if w.Matcher.Match(k) {
			break
		}
	}
	result <- k
}

func NewKeypair() keypair {
	privk, _ := wgtypes.GeneratePrivateKey()
	return keypair{
		privateKey: privk.String(),
		publicKey:  privk.PublicKey().String(),
	}
}
