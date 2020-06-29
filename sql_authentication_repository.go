package sql

import (
	"context"
	"errors"
	"fmt"
	"github.com/common-go/auth"
	"github.com/jinzhu/gorm"
	"strconv"
	"strings"
	"time"
)

type SqlAuthenticationRepository struct {
	db                      *gorm.DB
	userTableName           string
	passwordTableName       string
	TwoFactorRepository     auth.TwoFactorAuthenticationRepository
	activatedStatus         interface{}
	Status                  auth.StatusConfig
	IdName                  string
	UserName                string
	SuccessTimeName         string
	FailTimeName            string
	FailCountName           string
	LockedUntilTimeName     string
	StatusName              string
	PasswordChangedTimeName string
	PasswordName            string
	ContactName             string
	DisplayNameName         string
	MaxPasswordAgeName      string
	UserTypeName            string
	AccessDateFromName      string
	AccessDateToName        string
	AccessTimeFromName      string
	AccessTimeToName        string
	TwoFactorsName          string
}

func NewSqlAuthenticationRepositoryByConfig(db *gorm.DB, userTableName, passwordTableName string, twoFactorRepository auth.TwoFactorAuthenticationRepository, activatedStatus string, status auth.StatusConfig, c auth.SchemaConfig) *SqlAuthenticationRepository {
	return NewSqlAuthenticationRepository(db, userTableName, passwordTableName, twoFactorRepository, activatedStatus, status, c.Id, c.UserName, c.SuccessTime, c.FailTime, c.FailCount, c.LockedUntilTime, c.Status, c.PasswordChangedTime, c.Password, c.Contact, c.DisplayName, c.MaxPasswordAge, c.UserType, c.AccessDateFrom, c.AccessDateTo, c.AccessTimeFrom, c.AccessTimeTo, c.TwoFactors)
}

func NewSqlAuthenticationRepository(db *gorm.DB, userTableName, passwordTableName string, twoFactorRepository auth.TwoFactorAuthenticationRepository, activatedStatus string, status auth.StatusConfig, idName, userName, successTimeName, failTimeName, failCountName, lockedUntilTimeName, statusName, passwordChangedTimeName, passwordName, emailName, displayNameName, maxPasswordAgeName, userTypeName, accessDateFromName, accessDateToName, accessTimeFromName, accessTimeToName, twoFactorsName string) *SqlAuthenticationRepository {
	return &SqlAuthenticationRepository{
		db:                      db,
		userTableName:           strings.ToLower(userTableName),
		passwordTableName:       strings.ToLower(passwordTableName),
		TwoFactorRepository:     twoFactorRepository,
		activatedStatus:         strings.ToLower(activatedStatus),
		Status:                  status,
		IdName:                  strings.ToLower(idName),
		UserName:                strings.ToLower(userName),
		SuccessTimeName:         strings.ToLower(successTimeName),
		FailTimeName:            strings.ToLower(failTimeName),
		FailCountName:           strings.ToLower(failCountName),
		LockedUntilTimeName:     strings.ToLower(lockedUntilTimeName),
		StatusName:              strings.ToLower(statusName),
		PasswordChangedTimeName: strings.ToLower(passwordChangedTimeName),
		PasswordName:            strings.ToLower(passwordName),
		ContactName:             strings.ToLower(emailName),
		DisplayNameName:         strings.ToLower(displayNameName),
		MaxPasswordAgeName:      strings.ToLower(maxPasswordAgeName),
		UserTypeName:            strings.ToLower(userTypeName),
		AccessDateFromName:      strings.ToLower(accessDateFromName),
		AccessDateToName:        strings.ToLower(accessDateToName),
		AccessTimeFromName:      strings.ToLower(accessTimeFromName),
		AccessTimeToName:        strings.ToLower(accessTimeToName),
		TwoFactorsName:          strings.ToLower(twoFactorsName),
	}
}

func (r *SqlAuthenticationRepository) GetUserInfo(ctx context.Context, username string) (*auth.UserInfo, error) {
	userInfo := auth.UserInfo{}
	//result := auth.UserInfo{}
	//query := ""
	value := make(map[string]interface{})

	if r.userTableName == r.passwordTableName {
		//query = fmt.Sprintf("SELECT *
		//			FROM %s
		//			WHERE %s = ?")
		//query = fmt.Sprintf(query, r.userTableName, r.idName)
		rows, err := r.db.Table(r.userTableName).Where(r.UserName+" = ?", username).Select("*").Rows()
		//err := r.db.Table(r.userTableName).Raw(query, userName).Scan(&result).Pluck(r.statusName, &status).Error
		if err != nil {
			return nil, err
		}
		if !rows.Next() {
			if rows.Err() == nil {
				return nil, errors.New("not found")
			}
			return nil, rows.Err()
		}
		cols, errc := rows.Columns()
		if errc != nil {
			return nil, errc
		}
		length := len(cols)
		columns := make([]interface{}, length)
		temp := make([]interface{}, length)
		for i, _ := range columns {
			temp[i] = &columns[i]
		}
		if err := rows.Scan(temp...); err != nil {
			return nil, err
		}
		for i := 0; i < length; i++ {
			val := temp[i].(*interface{})
			k := cols[i]
			value[k] = *val
		}
	} else {
		join := "INNER JOIN " + r.passwordTableName + " on " + r.passwordTableName + "." + r.IdName + " = " + r.userTableName + "." + r.IdName
		rows, err1 := r.db.Table(r.userTableName).Where(r.userTableName+"."+r.UserName+"= ?", username).Joins(join).Select("*").Rows()
		if err1 != nil {
			return nil, err1
		}
		if !rows.Next() {
			if rows.Err() == nil {
				return nil, errors.New("not found")
			}
			return nil, rows.Err()
		}
		cols, errc := rows.Columns()
		if errc != nil {
			return nil, errc
		}
		length := len(cols)
		columns := make([]interface{}, length)
		temp := make([]interface{}, length)
		for i, _ := range columns {
			temp[i] = &columns[i]
		}
		if err := rows.Scan(temp...); err != nil {
			return nil, err
		}
		for i := 0; i < length; i++ {
			val := temp[i].(*interface{})
			k := cols[i]
			value[k] = *val
		}
	}
	if len(r.StatusName) > 0 {
		//rawStatus := raw.Lookup(r.StatusName)
		statusInfo, ok := value[r.StatusName]
		statusUserInfo := ""
		if ok {
			switch v := statusInfo.(type) {
			case int:
				statusUserInfo = strconv.Itoa(v)
			case int64:
				statusUserInfo = strconv.FormatInt(v, 10)
			case string:
				statusUserInfo = v
			case []uint8:
				statusUserInfo = string(v)
			case bool:
				statusUserInfo = strconv.FormatBool(v)
			default:
				return nil, fmt.Errorf(r.StatusName+": is of unsupported type %T", v)
			}
		}

		userInfo.Deactivated = statusUserInfo == r.Status.Deactivated
		userInfo.Suspended = statusUserInfo == r.Status.Suspended
		userInfo.Disable = statusUserInfo == r.Status.Disable
	}

	if len(r.IdName) > 0 {
		name, ok := value[r.IdName]
		if ok {
			if e, k := name.([]uint8); k {
				userInfo.UserId = string(e)
			} else if f, k := name.(int64); k {
				userInfo.UserId = strconv.FormatInt(f, 10)
			}
		}
	}
	if len(r.UserName) > 0 {
		name, ok := value[r.UserName]
		if ok {
			if e, k := name.([]uint8); k {
				userInfo.Username = string(e)
			}
		}
	}
	if len(r.ContactName) > 0 {
		email, ok := value[r.ContactName]
		if ok {
			if e, k := email.([]uint8); k {
				userInfo.Contact = string(e)
			}
		}
	}

	if len(r.DisplayNameName) > 0 {
		displayName, ok := value[r.DisplayNameName]
		if ok {
			if e, k := displayName.([]uint8); k {
				userInfo.DisplayName = string(e)
			}
		}
	}

	if len(r.MaxPasswordAgeName) > 0 {
		maxPasswordAge, ok := value[r.MaxPasswordAgeName]
		if ok {
			if e, k := maxPasswordAge.(int64); k {
				userInfo.MaxPasswordAge = int(e)
			}
		}
	}

	if len(r.UserTypeName) > 0 {
		maxPasswordAge, ok := value[r.UserTypeName]
		if ok {
			if e, k := maxPasswordAge.([]uint8); k {
				userInfo.UserType = string(e)
			}
		}
	}

	if len(r.AccessDateFromName) > 0 {
		accessDateFrom, ok := value[r.AccessDateFromName]
		if ok {
			if e, k := accessDateFrom.(time.Time); k {
				userInfo.AccessDateFrom = &e
			}
		}
	}
	if len(r.AccessDateToName) > 0 {
		accessDateTo, ok := value[r.AccessDateToName]
		if ok {
			if e, k := accessDateTo.(time.Time); k {
				userInfo.AccessDateTo = &e
			}
		}
	}

	if len(r.AccessTimeFromName) > 0 {
		accessTimeFrom, ok := value[r.AccessTimeFromName]
		if ok {
			if e, k := accessTimeFrom.(time.Time); k {
				userInfo.AccessTimeFrom = &e
			} else if s, k := accessTimeFrom.([]uint8); k {
				userInfo.AccessTimeFrom = getTime(string(s))
			}
		}
	}

	if len(r.AccessTimeToName) > 0 {
		accessTimeTo, ok := value[r.AccessTimeToName]
		if ok {
			if e, k := accessTimeTo.(time.Time); k {
				userInfo.AccessTimeTo = &e
			} else if s, k := accessTimeTo.([]uint8); k {
				userInfo.AccessTimeTo = getTime(string(s))
			}
		}
	}

	if len(r.PasswordName) > 0 {
		pass, ok := value[r.PasswordName]
		if ok {
			if e, k := pass.([]uint8); k {
				userInfo.Password = string(e)
			}
		}
	}

	if len(r.LockedUntilTimeName) > 0 {
		pass, ok := value[r.LockedUntilTimeName]
		if ok {
			if e, k := pass.(time.Time); k {
				userInfo.LockedUntilTime = &e
			}
		}
	}

	if len(r.SuccessTimeName) > 0 {
		pass, ok := value[r.SuccessTimeName]
		if ok {
			if e, k := pass.(time.Time); k {
				userInfo.SuccessTime = &e
			}
		}
	}

	if len(r.FailTimeName) > 0 {
		pass, ok := value[r.FailTimeName]
		if ok {
			if e, k := pass.(time.Time); k {
				userInfo.FailTime = &e
			}
		}
	}

	if len(r.FailCountName) > 0 {
		pass, ok := value[r.FailCountName]
		if ok {
			if e, k := pass.(int64); k {
				userInfo.FailCount = int(e)
			}
		}
	}

	if len(r.PasswordChangedTimeName) > 0 {
		pass, ok := value[r.PasswordChangedTimeName]
		if ok {
			if e, k := pass.(time.Time); k {
				userInfo.PasswordChangedTime = &e
			}
		}
	}

	if r.TwoFactorRepository != nil {
		id := userInfo.UserId
		if len(id) == 0 {
			id = username
		}
		ok, er2 := r.TwoFactorRepository.Require(ctx, id)
		if er2 != nil {
			return &userInfo, er2
		}
		userInfo.TwoFactors = ok
	} else if len(r.TwoFactorsName) > 0 {
		if isTwoFactor, ok := value[r.TwoFactorsName]; ok {
			if b, k := isTwoFactor.(bool); k {
				userInfo.TwoFactors = b
			}
		}
	}
	//
	//if r.userTableName == r.passwordTableName {
	//	return r.getPasswordInfo(ctx, &userInfo, &result)
	//}

	return &userInfo, nil
}

//func (r *SqlAuthenticationRepository) getPasswordInfo(ctx context.Context, user *auth.UserInfo, result *auth.UserInfo) (*auth.UserInfo, error) {
//	if len(r.passwordName) > 0 {
//		user.Password = result.Password
//	}
//
//	if len(r.lockedUntilTimeName) > 0 {
//		user.LockedUntilTime = result.LockedUntilTime
//	}
//
//	if len(r.successTimeName) > 0 {
//		user.SuccessTime = result.SuccessTime
//	}
//
//	if len(r.failTimeName) > 0 {
//		user.FailTime = result.FailTime
//	}
//
//	if len(r.failCountName) > 0 {
//		user.FailCount = result.FailCount
//	}
//
//	if len(r.passwordChangedTimeName) > 0 {
//		user.PasswordChangedTime = result.PasswordChangedTime
//	}
//	return user, nil
//}

func (r *SqlAuthenticationRepository) PassAuthentication(ctx context.Context, userId string) (int64, error) {
	return r.passAuthenticationAndActivate(ctx, userId, false)
}
func (r *SqlAuthenticationRepository) PassAuthenticationAndActivate(ctx context.Context, userId string) (int64, error) {
	return r.passAuthenticationAndActivate(ctx, userId, true)
}

func (r *SqlAuthenticationRepository) passAuthenticationAndActivate(ctx context.Context, userId string, updateStatus bool) (int64, error) {
	if len(r.SuccessTimeName) == 0 && len(r.FailCountName) == 0 && len(r.LockedUntilTimeName) == 0 {
		if !updateStatus {
			return 0, nil
		} else if len(r.StatusName) == 0 {
			return 0, nil
		}
	}
	pass := make(map[string]interface{})
	if len(r.SuccessTimeName) > 0 {
		pass[r.SuccessTimeName] = time.Now()
	}
	if len(r.FailCountName) > 0 {
		pass[r.FailCountName] = 0
	}
	if len(r.LockedUntilTimeName) > 0 {
		pass[r.LockedUntilTimeName] = nil
	}
	query := map[string]interface{}{
		r.IdName: userId,
	}

	if !updateStatus {
		return patch(r.db, r.passwordTableName, pass, query)
	}

	if r.userTableName == r.passwordTableName {
		pass[r.StatusName] = r.activatedStatus
		return patch(r.db, r.passwordTableName, pass, query)
	}

	k1, err := patch(r.db, r.passwordTableName, pass, query)
	if err != nil {
		return k1, err
	}

	user := make(map[string]interface{})
	user[r.IdName] = userId
	user[r.StatusName] = r.activatedStatus
	k2, err1 := patch(r.db, r.userTableName, user, query)
	return k1 + k2, err1
}

func (r *SqlAuthenticationRepository) WrongPassword(ctx context.Context, userId string, failCount int, lockedUntil *time.Time) error {
	if len(r.FailTimeName) == 0 && len(r.FailCountName) == 0 && len(r.LockedUntilTimeName) == 0 {
		return nil
	}
	pass := make(map[string]interface{})
	pass[r.IdName] = userId
	if len(r.FailTimeName) > 0 {
		pass[r.FailTimeName] = time.Now()
	}
	if len(r.FailCountName) > 0 {
		pass[r.FailCountName] = failCount
		if len(r.LockedUntilTimeName) > 0 {
			pass[r.LockedUntilTimeName] = lockedUntil
		}
	}
	query := map[string]interface{}{
		r.IdName: userId,
	}
	_, err := patch(r.db, r.passwordTableName, pass, query)
	return err
}

func getTime(accessTime string) *time.Time {
	const LAYOUT = "2006-01-02T15:04"
	if len(accessTime) > 0 {
		today := time.Now()
		location := time.Now().Location()
		x := today.Format("2006-01-02") + "T" + accessTime
		t, e := time.ParseInLocation(LAYOUT, x, location)
		if e == nil {
			return &t
		}
	}
	return nil
}

func patch(db *gorm.DB, table string, model map[string]interface{}, query map[string]interface{}) (int64, error) {
	result := db.Table(table).Where(query).Updates(model)
	if err := result.Error; err != nil {
		return result.RowsAffected, err
	}
	return result.RowsAffected, nil
}
