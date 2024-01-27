package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
)

func readLines(file string) (lines []string) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("Error opening input file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	// check if scanner raises any error
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input file:", err)
	}
	return lines
}

func lines2Data(lines []string) (data []byte) {
	for _, line := range lines {
		data = append(data, []byte(line)...)
		data = append(data, '\n')
	}
	return data
}

func extractBaseCall(input string) string {
	parts := strings.Split(input, "$")
	if len(parts) > 0 {
		return parts[0]
	}
	return input
}

func writeProg(lines []string, outFile string) {
	// create output fd
	out, err := os.Create(outFile)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer out.Close()

	for _, line := range lines {
		// write to output fd
		_, err := fmt.Fprintln(out, line)
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	}
}

// Function to split the string into words and calculate term frequency
func stringToTermFrequency(str string) map[string]float64 {
	termFreq := make(map[string]float64)
	words := strings.Fields(str)
	for _, word := range words {
		termFreq[word]++
	}
	return termFreq
}

// Function to calculate the dot product of two term frequencies
func dotProduct(tf1, tf2 map[string]float64) float64 {
	var dot float64
	for word, freq := range tf1 {
		if freq2, exists := tf2[word]; exists {
			dot += freq * freq2
		}
	}
	return dot
}

// Function to calculate the magnitude of a term frequency vector
func magnitude(tf map[string]float64) float64 {
	var mag float64
	for _, freq := range tf {
		mag += freq * freq
	}
	return math.Sqrt(mag)
}

// Function to calculate cosine similarity. The more similar, the more close to 1
func cosineSimilarity(str1, str2 string) float64 {
	s1 := strings.ReplaceAll(str1, "$", " ")
	s1 = strings.ReplaceAll(s1, "_", " ")
	s2 := strings.ReplaceAll(str2, "$", " ")
	s2 = strings.ReplaceAll(s2, "_", " ")
	tf1 := stringToTermFrequency(s1)
	tf2 := stringToTermFrequency(s2)
	dot := dotProduct(tf1, tf2)
	mag1 := magnitude(tf1)
	mag2 := magnitude(tf2)
	if mag1 == 0 || mag2 == 0 {
		return 0
	}
	return dot / (mag1 * mag2)
}

// Function to get max k similar
func maxKSim(src string, dsts []string, k int) (kSims []string) {
	similarities := make(map[string]float64)

	for _, dst := range dsts {
		similarity := cosineSimilarity(src, dst)
		similarities[dst] = similarity
	}

	// Custom sorting function to sort by similarity in descending order
	var sortedDsts []string
	for dst := range similarities {
		sortedDsts = append(sortedDsts, dst)
	}

	sort.Slice(sortedDsts, func(i, j int) bool {
		return similarities[sortedDsts[i]] > similarities[sortedDsts[j]]
	})

	if k <= len(sortedDsts) {
		return sortedDsts[:k]
	}
	return sortedDsts
}

func replaceCharAtIndex(input string, j int, wantChar string) string {
	if j < 0 || j > len(input) {
		return input // Invalid index, return the original string
	}

	if j == len(input) {
		return input + wantChar
	}

	// Convert string to rune slice
	runes := []rune(input)

	// Update the desired index
	runes[j] = []rune(wantChar)[0]

	// Convert back to string
	modifiedString := string(runes)

	return modifiedString
}

func fixUnbalancedParentheses(input string) string {
	var stack []rune
	var result strings.Builder

	for _, char := range input {
		if char == '(' || char == '{' {
			stack = append(stack, char)
		} else if char == ')' || char == '}' {
			if len(stack) > 0 && isMatchingPair(stack[len(stack)-1], char) {
				stack = stack[:len(stack)-1]
			} else {
				// Unbalanced right parenthesis, add a corresponding left parenthesis
				left := getMatchingLeft(char)
				result.WriteRune(left)
				stack = append(stack, left)
			}
		}

		result.WriteRune(char)
	}

	// Add the corresponding right parentheses for unbalanced left parentheses
	for i := len(stack) - 1; i >= 0; i-- {
		result.WriteRune(getMatchingRight(stack[i]))
	}

	return result.String()
}

func isMatchingPair(left, right rune) bool {
	return (left == '(' && right == ')') || (left == '{' && right == '}')
}

func getMatchingLeft(right rune) rune {
	if right == ')' {
		return '('
	} else if right == '}' {
		return '{'
	}
	return 0
}

func getMatchingRight(left rune) rune {
	if left == '(' {
		return ')'
	} else if left == '{' {
		return '}'
	}
	return 0
}
