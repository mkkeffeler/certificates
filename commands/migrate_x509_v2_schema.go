package commands

import (
	"fmt"

	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
)

func init() {
	command.Register(cli.Command{
		Name:      "migrate-x509-v2-schema",
		Usage:     "Migrate an existing x509 schema to V2 so that you can query already signed certificates with the flexibility provided by the new schema. To only be used one time.",
		UsageText: "**step-ca migrate-x509-v2-schema",
		Action:    migrateX509Action,
		Description: `**step-ca migrate-x509-v2-schema** reads your existing x509_certs and converts them to the new schema, so you can query them.

'''
$ step-ca migrate-x509-v2-schema <configFile>

## POSITIONAL ARGUMENTS

<configFile>
:  The path to your config file.

'''`,
	})
}

func migrateX509Action(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return cli.ShowCommandHelp(ctx, "onboard")
	}
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	fmt.Println("Migrating the x509_certs table to use the new schema. This is a one time operation, and should only be used 1 time.")
	configFile := ctx.Args().Get(0)
	config, err := config.LoadConfiguration(configFile)
	if err != nil {
		return err
	}

	db, err := db.New(config.DB)
	if err != nil {
		return err
	}

	dbCertCount, getCertSignedCountErr := db.GetCertificateSignedCount()
	fmt.Println("There is a total of ")
	fmt.Println(dbCertCount)
	fmt.Println("Certificates in your database")

	if getCertSignedCountErr != nil {
		return getCertSignedCountErr
	}
	totalCertsReviewed := 0
	pageSize := 100
	page := 0
	for totalCertsReviewed < dbCertCount {
		fmt.Println("Processing page ")
		fmt.Println(page)
		dbEntries, getCertErr := db.GetCertificatePage(pageSize, totalCertsReviewed)
		if getCertErr != nil {
			return getCertErr
		}

		for _, entry := range dbEntries {
			if !entry.SubjectNotAfter.Valid && !entry.SubjectCommonName.Valid {
				fmt.Println("This Cert Serial Number needs to be migrated to the new schema")
				fmt.Println(string(entry.Key))
				fmt.Println("Updating above Serial Number to use new schema")
				cert, err := x509.ParseCertificate(entry.Value)
				if err != nil {
					return errors.Wrapf(err, "error parsing certificate with serial number %s", string(entry.Key))
				}
				certError := db.StoreCertificate(cert)
				if certError != nil {
					return errors.Wrapf(err, "Error storing updated cert with serial number %s", string(entry.Key))
				}
			}
		}
		totalCertsReviewed += pageSize
		page++

	}

	fmt.Println("Obtained all Certs, Migrated to new schema.")

	return nil
}
