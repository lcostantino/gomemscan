//build +yara_support
package main


func getYaraEngine
engine = "yara"
		c, err := yara.NewCompiler()
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: Cannot initialize YARA compiler => %s"), au.BrightBlue(err)))
			os.Exit(1)
		}
		f, err := os.Open(args.yaraFile)
		defer f.Close()
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: Cannot open yara rule file => %s"), au.BrightBlue(err)))
			os.Exit(1)
		}
		err = c.AddFile(f, "main")

		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: Cannot parse yara rule => %s"), au.BrightBlue(err)))
			os.Exit(1)
		}
		rules, err := c.GetRules()

		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: Cannot compile rules => %s"), au.BrightBlue(err)))
			os.Exit(1)
		}
		yscanners := make([]*yara.Scanner, args.totalGoRoutines)
		for x := 0; x < args.totalGoRoutines; x++ {
			yscanners[x], _ = yara.NewScanner(rules)
		}

		matchMode = func(chunk *[]byte, location memscan.MemRange, workerNum int) bool {
			var m yara.MatchRules

			yscanners[workerNum].SetCallback(&m).ScanMem(*chunk)
			if len(m) > 0 {

				matchPositions := make([][]int, 0, 10)
				for _, match := range m {
					for _, pos := range match.Strings {
						sindex := []int{int(pos.Offset), int(pos.Offset) + len(pos.Data)}
						matchPositions = append(matchPositions, sindex)
					}

				}
				smutex.Lock()
				defer smutex.Unlock()
				//Warning: this store all memory regardeless contextLength
				if args.justMatch {
					chunk = nil
				}
				matches = append(matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})
				return true
			}

			return false
		}