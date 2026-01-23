package persistence

import "database/sql"

func (s *Service) GetConfiguration(name string) ([]byte, error) {
	var setting []byte

	if err := s.stmtGetConfiguration.Get(&setting, struct {
		Name string `db:"name"`
		Key  string `db:"key"`
	}{
		Name: name,
		Key:  s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	return setting, nil
}

func (s *Service) InsertConfiguration(name string, setting []byte) error {
	if _, err := s.stmtInsertConfiguration.Exec(struct {
		Name    string `db:"name"`
		Setting []byte `db:"setting"`
		Key     string `db:"key"`
	}{
		Name:    name,
		Setting: setting,
		Key:     s.config.Database.EncryptionKey,
	}); err != nil {
		return err
	}

	return nil
}
