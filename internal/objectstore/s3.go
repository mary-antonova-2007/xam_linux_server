package objectstore

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Client struct {
	minio      *minio.Client
	bucketName string
	presignTTL time.Duration
}

func New(endpoint, accessKey, secretKey, bucket string, useSSL bool, presignTTL time.Duration) (*Client, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		minio:      client,
		bucketName: bucket,
		presignTTL: presignTTL,
	}, nil
}

func (c *Client) EnsureBucket(ctx context.Context) error {
	exists, err := c.minio.BucketExists(ctx, c.bucketName)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return c.minio.MakeBucket(ctx, c.bucketName, minio.MakeBucketOptions{})
}

func (c *Client) PresignedPut(ctx context.Context, objectKey string, mimeType string) (*url.URL, error) {
	return c.minio.PresignedPutObject(ctx, c.bucketName, objectKey, c.presignTTL)
}

func (c *Client) PresignedGet(ctx context.Context, objectKey string) (*url.URL, error) {
	return c.minio.PresignedGetObject(ctx, c.bucketName, objectKey, c.presignTTL, nil)
}

func (c *Client) PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, mimeType string) error {
	_, err := c.minio.PutObject(ctx, c.bucketName, objectKey, reader, size, minio.PutObjectOptions{
		ContentType: mimeType,
	})
	return err
}

func (c *Client) GetObject(ctx context.Context, objectKey string) (io.ReadCloser, error) {
	object, err := c.minio.GetObject(ctx, c.bucketName, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := object.Stat(); err != nil {
		_ = object.Close()
		return nil, err
	}
	return object, nil
}

func (c *Client) RemoveObject(ctx context.Context, objectKey string) error {
	return c.minio.RemoveObject(ctx, c.bucketName, objectKey, minio.RemoveObjectOptions{})
}

func (c *Client) Health(ctx context.Context) error {
	exists, err := c.minio.BucketExists(ctx, c.bucketName)
	if err != nil {
		return fmt.Errorf("s3 health check failed: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", c.bucketName)
	}
	return nil
}
