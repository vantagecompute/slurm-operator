// SPDX-FileCopyrightText: Copyright (C) SchedMD LLC.
// SPDX-License-Identifier: Apache-2.0

package restapibuilder

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	slinkyv1beta1 "github.com/SlinkyProject/slurm-operator/api/v1beta1"
	"github.com/SlinkyProject/slurm-operator/internal/builder/common"
	controllerbuilder "github.com/SlinkyProject/slurm-operator/internal/builder/controllerbuilder"
	"github.com/SlinkyProject/slurm-operator/internal/builder/labels"
	"github.com/SlinkyProject/slurm-operator/internal/builder/metadata"
)

const (
	SlurmrestdPort = 6820

	// Run slurmrestd as the SlurmUser (uid 401). Required for auth/jwt daemon-mode
	// signing: Slurm refuses to load /etc/slurm/jwt.key unless the file is owned by
	// SlurmUser AND the reading process itself runs as SlurmUser (mode 0600). With
	// the previous value (65534/nobody), every auth-requiring RPC to slurmctld
	// failed ESLURM_PROTOCOL_AUTHENTICATION_ERROR (1007) because slurmrestd couldn't
	// build a valid daemon credential locally. The upstream slurmrestd image ships
	// with a `slurm` user (uid 401, gid 401).
	slurmrestdUser    = "slurm"
	slurmrestdUserUid = int64(401)
	slurmrestdUserGid = slurmrestdUserUid
)

func (b *RestapiBuilder) BuildRestapi(restapi *slinkyv1beta1.RestApi) (*appsv1.Deployment, error) {
	key := restapi.Key()

	selectorLabels := labels.NewBuilder().
		WithRestapiSelectorLabels(restapi).
		Build()
	objectMeta := metadata.NewBuilder(key).
		WithAnnotations(restapi.Annotations).
		WithLabels(restapi.Labels).
		WithMetadata(restapi.Spec.Template.Metadata).
		WithLabels(labels.NewBuilder().WithRestapiLabels(restapi).Build()).
		Build()

	podTemplate, err := b.restapiPodTemplate(restapi)
	if err != nil {
		return nil, fmt.Errorf("failed to build pod template: %w", err)
	}

	o := &appsv1.Deployment{
		ObjectMeta: objectMeta,
		Spec: appsv1.DeploymentSpec{
			Replicas:             restapi.Spec.Replicas,
			RevisionHistoryLimit: ptr.To[int32](0),
			Selector: &metav1.LabelSelector{
				MatchLabels: selectorLabels,
			},
			Template: podTemplate,
		},
	}

	if err := controllerutil.SetControllerReference(restapi, o, b.client.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to set owner controller: %w", err)
	}

	return o, nil
}

func (b *RestapiBuilder) restapiPodTemplate(restapi *slinkyv1beta1.RestApi) (corev1.PodTemplateSpec, error) {
	ctx := context.TODO()
	key := restapi.Key()

	controller, err := b.refResolver.GetController(ctx, restapi.Spec.ControllerRef)
	if err != nil {
		return corev1.PodTemplateSpec{}, err
	}

	hasAccounting := !apiequality.Semantic.DeepEqual(controller.Spec.AccountingRef, slinkyv1beta1.ObjectReference{})

	objectMeta := metadata.NewBuilder(key).
		WithAnnotations(restapi.Annotations).
		WithLabels(restapi.Labels).
		WithMetadata(restapi.Spec.Template.Metadata).
		WithLabels(labels.NewBuilder().WithRestapiLabels(restapi).Build()).
		WithAnnotations(map[string]string{
			annotationDefaultContainer: labels.RestapiApp,
		}).
		Build()

	spec := restapi.Spec
	template := spec.Template.PodSpecWrapper

	opts := common.PodTemplateOpts{
		Key: key,
		Metadata: slinkyv1beta1.Metadata{
			Annotations: objectMeta.Annotations,
			Labels:      objectMeta.Labels,
		},
		Base: corev1.PodSpec{
			AutomountServiceAccountToken: ptr.To(false),
			Containers: []corev1.Container{
				b.slurmrestdContainer(spec.Slurmrestd.Container, hasAccounting),
			},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr.To(true),
				RunAsUser:    ptr.To(slurmrestdUserUid),
				RunAsGroup:   ptr.To(slurmrestdUserGid),
				FSGroup:      ptr.To(slurmrestdUserGid),
			},
			Volumes: restapiVolumes(controller),
		},
		Merge: template.PodSpec,
	}

	return b.CommonBuilder.BuildPodTemplate(opts), nil
}

func restapiVolumes(controller *slinkyv1beta1.Controller) []corev1.Volume {
	sources := []corev1.VolumeProjection{
		{
			ConfigMap: &corev1.ConfigMapProjection{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: controller.ConfigKey().Name,
				},
				Items: []corev1.KeyToPath{
					{Key: controllerbuilder.SlurmConfFile, Path: controllerbuilder.SlurmConfFile},
				},
			},
		},
		{
			Secret: &corev1.SecretProjection{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: controller.AuthSlurmRef().Name,
				},
				Items: []corev1.KeyToPath{
					{Key: controller.AuthSlurmRef().Key, Path: common.SlurmKeyFile},
				},
			},
		},
	}

	// slurmrestd runs with SLURM_JWT=daemon (set unconditionally in slurmrestdContainer),
	// which signs the daemon credential for RPCs to slurmctld with the shared jwt.key.
	// Without this mount, every auth-requiring RPC fails
	// ESLURM_PROTOCOL_AUTHENTICATION_ERROR (1007) — /ping still works because slurmctld
	// handles REQUEST_PING without a full auth check. The Controller already projects the
	// same secret at /etc/slurm/jwt.key; mirror it here so slurmrestd can sign tokens.
	if jwtRef := controller.AuthJwtRef(); jwtRef.Name != "" {
		sources = append(sources, corev1.VolumeProjection{
			Secret: &corev1.SecretProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: jwtRef.Name},
				Items: []corev1.KeyToPath{
					{Key: jwtRef.Key, Path: common.JwtKeyFile},
				},
			},
		})
	}

	// Mirror the Controller's JWKS projection so slurmrestd's rest_auth/jwt plugin can
	// verify user-presented OIDC/Keycloak JWTs against the same JWKS slurmctld uses.
	// Only mounted when JwksKeyRef is set on the Controller (jwksKeys.enabled=true).
	if jwksRef := controller.AuthJwksRef(); jwksRef != nil && jwksRef.Name != "" {
		sources = append(sources, corev1.VolumeProjection{
			ConfigMap: &corev1.ConfigMapProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: jwksRef.Name},
				Items: []corev1.KeyToPath{
					{Key: jwksRef.Key, Path: common.JwksKeyFile},
				},
			},
		})
	}

	return []corev1.Volume{
		{
			Name: common.SlurmEtcVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: ptr.To[int32](0o600),
					Sources:     sources,
				},
			},
		},
	}
}

func (b *RestapiBuilder) slurmrestdContainer(merge corev1.Container, hasAccounting bool) corev1.Container {
	opts := common.ContainerOpts{
		Base: corev1.Container{
			Name: labels.RestapiApp,
			Env: []corev1.EnvVar{
				{Name: "SLURM_JWT", Value: "daemon"},
				{Name: "SLURMRESTD_SECURITY", Value: strings.Join([]string{
					"disable_unshare_files",
					"disable_unshare_sysv",
				}, ",")},
			},
			Args: slurmrestdArgs(hasAccounting),
			Ports: []corev1.ContainerPort{
				{
					Name:          labels.RestapiApp,
					ContainerPort: SlurmrestdPort,
					Protocol:      corev1.ProtocolTCP,
				},
			},
			StartupProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(SlurmrestdPort),
					},
				},
				FailureThreshold: 6,
				PeriodSeconds:    10,
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(SlurmrestdPort),
					},
				},
				FailureThreshold: 6,
				PeriodSeconds:    10,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(SlurmrestdPort),
					},
				},
			},
			SecurityContext: &corev1.SecurityContext{
				RunAsNonRoot: ptr.To(true),
				RunAsUser:    ptr.To(slurmrestdUserUid),
				RunAsGroup:   ptr.To(slurmrestdUserGid),
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: common.SlurmEtcVolume, MountPath: common.SlurmEtcDir, ReadOnly: true},
			},
		},
		Merge: merge,
	}

	out := b.CommonBuilder.BuildContainer(opts)

	// Usage: slurmrestd [OPTIONS] [host:port]...
	out.Args = append(out.Args, fmt.Sprintf("0.0.0.0:%d", SlurmrestdPort))

	return out
}

func slurmrestdArgs(hasAccounting bool) []string {
	args := []string{}
	if !hasAccounting {
		args = append(args, "-s")
		args = append(args, "openapi/slurmctld")
	}
	return args
}
