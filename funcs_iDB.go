package main

func parse_iDB_Peer_Vocabulary() (ok bool) {
	for _, value := range i_peer {
		var (
			_v_AB_list          = make(map[_Name]bool)
			_v_Application_list = make(map[_Name]bool)
		)
		for _, b := range value.Source {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.Source_AB) == 0 {
						case false:
							_v_AB_list[z.Source_AB] = true
						}
						switch len(z.Destination_AB) == 0 {
						case false:
							_v_AB_list[z.Destination_AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.Destination {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.Source_AB) == 0 {
						case false:
							_v_AB_list[z.Source_AB] = true
						}
						switch len(z.Destination_AB) == 0 {
						case false:
							_v_AB_list[z.Destination_AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.SP_Exact {
			for _, x := range b.Rule {
				for _, z := range x.Match {
					switch len(z.Source_AB) == 0 {
					case false:
						_v_AB_list[z.Source_AB] = true
					}
					switch len(z.Destination_AB) == 0 {
					case false:
						_v_AB_list[z.Destination_AB] = true
					}
					switch len(z.Application) == 0 {
					case false:
						_v_Application_list[z.Application] = true
					}
				}
			}
		}
		for _, x := range value.SP_Global {
			for _, z := range x.Match {
				switch len(z.Source_AB) == 0 {
				case false:
					_v_AB_list[z.Source_AB] = true
				}
				switch len(z.Destination_AB) == 0 {
				case false:
					_v_AB_list[z.Destination_AB] = true
				}
				switch len(z.Application) == 0 {
				case false:
					_v_Application_list[z.Application] = true
				}
			}
		}

		_v_AB_list = _AB_rparse(_v_AB_list)

		for a := range _v_AB_list {
			value.AB[a] = pdb_ab[a]
		}
		for a := range _v_Application_list {
			value.Application[a] = pdb_appl[a]
		}
	}
	return true
}
